using System.Collections.Concurrent;
using System.Net;
using DnsClient.Protocol;
using FilterDns.Alert;
using FilterDns.Cache;
using FilterDns.Config;
using FilterDns.Export;
using FilterDns.Filter;
using FilterDns.Notify;
using FilterDns.Recovery;
using FilterDns.Upstream;
using FilterDns.Verify;
using FilterDns.Whitelist;
using FilterDns.Xfer;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Text;

namespace FilterDns.Proxy;

public class DnsProxyServer : BackgroundService
{
    private readonly AppConfiguration _config;
    private readonly ILogger<DnsProxyServer> _logger;
    private readonly ILoggerFactory _loggerFactory;
    private readonly Dictionary<string, (ZoneConfig Config, IpWhitelist Whitelist)> _zones;
    private readonly ZoneCache _cache;
    private readonly Dictionary<string, NotifySender> _notifySenders;
    private readonly SlaveVerificationService? _verificationService;
    private readonly ConcurrentDictionary<string, ZoneHistory> _zoneHistories;
    private readonly ZoneHistoryStorage? _historyStorage;
    private readonly ConcurrentDictionary<string, SemaphoreSlim> _zoneUpdateSemaphores;
    private readonly SelfRestartService _selfRestartService;
    private XferHandler? _xferHandler;

    // === RAPID UPDATE HANDLING STATE ===
    
    /// <summary>
    /// Tracks pending debounced NOTIFY processing per zone.
    /// Key: zone name, Value: (last NOTIFY time, cancellation token source for pending update)
    /// </summary>
    private readonly ConcurrentDictionary<string, (DateTime LastNotify, CancellationTokenSource? PendingCts)> _notifyDebounce = new();

    /// <summary>
    /// Tracks the last time NOTIFY was sent to slaves per zone.
    /// Used to enforce minimum interval between slave notifications.
    /// </summary>
    private readonly ConcurrentDictionary<string, DateTime> _lastSlaveNotifyTime = new();

    /// <summary>
    /// Tracks recent update timestamps per zone for detecting rapid update patterns.
    /// Key: zone name, Value: list of update timestamps
    /// </summary>
    private readonly ConcurrentDictionary<string, List<DateTime>> _recentUpdateTimestamps = new();

    public DnsProxyServer(
        AppConfiguration config, 
        ILogger<DnsProxyServer> logger, 
        ILoggerFactory loggerFactory,
        EmailAlertService? emailAlertService = null)
    {
        _config = config;
        _logger = logger;
        _loggerFactory = loggerFactory;
        _cache = new ZoneCache();
        _zones = new Dictionary<string, (ZoneConfig, IpWhitelist)>();
        _notifySenders = new Dictionary<string, NotifySender>();
        _zoneHistories = new ConcurrentDictionary<string, ZoneHistory>();
        _zoneUpdateSemaphores = new ConcurrentDictionary<string, SemaphoreSlim>();

        // Initialize self-restart service for recovery from unrecoverable situations
        var selfRestartLogger = _loggerFactory.CreateLogger<SelfRestartService>();
        _selfRestartService = new SelfRestartService(config.Server.SelfRestart, selfRestartLogger);

        // Initialize history storage if data directory is configured
        var dataDirectory = config.Server.DataDirectory ?? "./data";
        var historyLogger = _loggerFactory.CreateLogger<ZoneHistoryStorage>();
        var exportBindZoneFiles = config.Server.ExportBindZoneFiles;
        var securityConfig = config.Server.Security;
        _historyStorage = new ZoneHistoryStorage(dataDirectory, historyLogger, exportBindZoneFiles, securityConfig);

        // Build zones and whitelists
        foreach (var zoneConfig in config.Zones)
        {
            var whitelistEntries = new List<string>(zoneConfig.XferWhitelist);
            
            // Filter out invalid slaves and automatically add valid slave IPs to whitelist
            var validSlaves = new List<SlaveConfig>();
            foreach (var slave in zoneConfig.Slaves)
            {
                if (slave.IsValid())
                {
                    var ipAddress = slave.GetIpAddress();
                    if (ipAddress != null)
                    {
                        whitelistEntries.Add(ipAddress.ToString());
                        validSlaves.Add(slave);
                    }
                }
                else
                {
                    _logger.LogWarning("Skipping invalid slave configuration for zone {Zone}: Ip={Ip}, Port={Port}", 
                        zoneConfig.Name, slave.Ip, slave.Port);
                }
            }

            var whitelist = new IpWhitelist(whitelistEntries);
            _zones[zoneConfig.Name] = (zoneConfig, whitelist);

            // Create notify sender for this zone using only valid slaves
            var notifyLogger = _loggerFactory.CreateLogger<NotifySender>();
            _notifySenders[zoneConfig.Name] = new NotifySender(validSlaves, notifyLogger);

            // Create semaphore for serializing zone updates (1 concurrent update per zone)
            _zoneUpdateSemaphores[zoneConfig.Name] = new SemaphoreSlim(1, 1);
        }

        // Create verification service (shared across all zones)
        var verificationLogger = _loggerFactory.CreateLogger<SlaveVerificationService>();
        _verificationService = new SlaveVerificationService(verificationLogger, emailAlertService, _selfRestartService);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("Starting DNS Proxy Server");

        // Initialize health check whitelist
        var healthCheckWhitelist = new IpWhitelist(_config.Server.HealthCheckAcl ?? new List<string>());

        // Load zone histories from disk BEFORE starting the server
        await LoadZoneHistoriesAsync(stoppingToken);

        // Poll all zones immediately on startup BEFORE starting the DNS server
        // This ensures zones are fully cached and ready before accepting IXFR requests
        _logger.LogInformation("Performing initial zone poll for all configured zones...");
        var initialPollTasks = _zones.Select(async kvp =>
        {
            try
            {
                await PollUpstreamZoneOnceAsync(kvp.Key, kvp.Value.Config, stoppingToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Initial poll for zone {Zone} cancelled during shutdown", kvp.Key);
            }
            catch (Exception ex)
            {
                if (!stoppingToken.IsCancellationRequested)
                {
                    _logger.LogError(ex, "Error during initial poll for zone {Zone}", kvp.Key);
                }
                else
                {
                    _logger.LogDebug("Error during initial poll for zone {Zone} during shutdown: {Message}", kvp.Key, ex.Message);
                }
            }
        });
        
        try
        {
            await Task.WhenAll(initialPollTasks);
            _logger.LogInformation("Initial zone poll completed for all zones");
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Initial zone poll cancelled during shutdown");
        }

        // Initialize XFER handler using injected logger factory
        var xferLogger = _loggerFactory.CreateLogger<XferHandler>();
        var ixfrResponseMode = _config.Server.IxfrResponseMode ?? "Incremental";
        var securityConfig = _config.Server.Security;
        _xferHandler = new XferHandler(
            _zones,
            _cache,
            _config.Server.ListenAddress,
            _config.Server.ListenPort,
            xferLogger,
            healthCheckWhitelist,
            onNotifyReceived: HandleNotifyFromUpstreamAsync,
            getHistory: GetZoneHistory,
            onZoneUpdatedDuringTransfer: HandleZoneUpdatedDuringTransferAsync,
            ixfrResponseMode: ixfrResponseMode,
            securityConfig: securityConfig);

        // Start DNS server AFTER initial zone poll completes
        // This ensures zones are fully cached and ready before accepting connections
        await _xferHandler.StartAsync(stoppingToken);

        // Start background polling tasks for each zone (only if polling is enabled)
        var pollingTasks = _zones
            .Where(kvp =>
            {
                var pollInterval = kvp.Value.Config.PollInterval ?? _config.Server.UpstreamPollInterval;
                return pollInterval > 0;
            })
            .Select(kvp =>
            {
                var pollInterval = kvp.Value.Config.PollInterval ?? _config.Server.UpstreamPollInterval;
                _logger.LogInformation("Starting background polling for zone {Zone} (interval: {Interval}s)", 
                    kvp.Key, pollInterval);
                return PollUpstreamZoneAsync(kvp.Key, kvp.Value.Config, stoppingToken);
            })
            .ToList();

        // Log zones where polling is disabled
        var disabledPollingZones = _zones
            .Where(kvp =>
            {
                var pollInterval = kvp.Value.Config.PollInterval ?? _config.Server.UpstreamPollInterval;
                return pollInterval <= 0;
            })
            .Select(kvp => kvp.Key)
            .ToList();

        if (disabledPollingZones.Any())
        {
            _logger.LogInformation("Polling disabled for zones: {Zones} (UpstreamPollInterval is 0)", 
                string.Join(", ", disabledPollingZones));
        }

        // Start history cleanup task if configured
        var cleanupTask = StartHistoryCleanupTaskAsync(stoppingToken);

        try
        {
            await Task.WhenAll(pollingTasks.Concat(new[] { cleanupTask }));
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Background tasks cancelled during shutdown");
        }
    }

    private async Task HandleNotifyFromUpstreamAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        CancellationToken cancellationToken)
    {
        // Get debounce time (per-zone override or server default)
        var debounceMs = zoneConfig.NotifyDebounceMs ?? _config.Server.NotifyDebounceMs;
        
        // Cap debounce time to prevent excessive delays
        debounceMs = Math.Min(debounceMs, Constants.MaxNotifyDebounceMs);

        // If debouncing is disabled (0), process immediately
        if (debounceMs <= 0)
        {
            _logger.LogInformation("NOTIFY-triggered update: Processing zone {Zone} from upstream {Upstream} (debouncing disabled)", 
                zoneName, zoneConfig.Upstream);
            await UpdateZoneFromUpstreamAsync(zoneName, zoneConfig, cancellationToken, triggeredByNotify: true);
            return;
        }

        // Debounce logic: cancel any pending update for this zone and schedule a new one
        var now = DateTime.UtcNow;
        
        // Get current state and cancel pending update if exists
        if (_notifyDebounce.TryGetValue(zoneName, out var existing) && existing.PendingCts != null)
        {
            try
            {
                existing.PendingCts.Cancel();
                _logger.LogDebug(
                    "NOTIFY-triggered update: Cancelled pending debounced update for zone {Zone} (new NOTIFY received, last: {LastMs}ms ago)",
                    zoneName, (now - existing.LastNotify).TotalMilliseconds);
            }
            catch (ObjectDisposedException)
            {
                // CTS was already disposed, ignore
            }
        }

        // Create new cancellation token for this debounced update
        var newCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _notifyDebounce[zoneName] = (now, newCts);

        _logger.LogDebug(
            "NOTIFY-triggered update: Debouncing zone {Zone} for {DebounceMs}ms (waiting for quiet period)",
            zoneName, debounceMs);

        try
        {
            // Wait for debounce period - if another NOTIFY arrives, this will be cancelled
            await Task.Delay(debounceMs, newCts.Token);

            // If we get here, no new NOTIFY arrived during debounce period
            _logger.LogInformation(
                "NOTIFY-triggered update: Processing zone {Zone} from upstream {Upstream} after {DebounceMs}ms debounce",
                zoneName, zoneConfig.Upstream, debounceMs);

            await UpdateZoneFromUpstreamAsync(zoneName, zoneConfig, cancellationToken, triggeredByNotify: true);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Debounce was cancelled due to new NOTIFY - this is expected, log at debug level
            _logger.LogDebug(
                "NOTIFY-triggered update: Debounced update for zone {Zone} superseded by newer NOTIFY",
                zoneName);
        }
        catch (OperationCanceledException)
        {
            // Application shutdown - rethrow
            throw;
        }
        finally
        {
            // Clean up CTS if it's still ours
            if (_notifyDebounce.TryGetValue(zoneName, out var current) && current.PendingCts == newCts)
            {
                _notifyDebounce.TryUpdate(zoneName, (current.LastNotify, null), current);
            }
            
            try
            {
                newCts.Dispose();
            }
            catch (ObjectDisposedException)
            {
                // Already disposed
            }
        }
    }

    /// <summary>
    /// Callback for when XferHandler updates the cache during zone transfer handling.
    /// This ensures zone history is updated and other slaves are notified when the cache
    /// is updated outside of the normal polling/NOTIFY flow.
    /// </summary>
    private async Task HandleZoneUpdatedDuringTransferAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        List<FilteredRecord> records,
        uint newSerial,
        CancellationToken cancellationToken)
    {
        _logger.LogDebug("Zone {Zone} updated during transfer handling to serial {Serial}, updating history and notifying slaves", 
            zoneName, newSerial);

        // Save current cached version to history BEFORE we consider it replaced
        // Note: The cache was already updated by XferHandler, so we get the "previous" version
        // from history if available, or skip if this is the first version
        // Actually, the cache is already updated at this point, so we need to handle this differently
        // We'll just update history with the new version and send NOTIFY

        // Update zone history for IXFR support - add the new version
        await UpdateZoneHistoryAsync(zoneName, zoneConfig, records, newSerial);

        // Record this update for rapid update detection
        RecordUpdateTimestamp(zoneName);

        // Send NOTIFY to all slaves
        if (_notifySenders.TryGetValue(zoneName, out var notifySender))
        {
            // Small delay to ensure zone is fully ready before sending NOTIFY
            await Task.Delay(Constants.NotifyDelayMs, cancellationToken);

            var logPrefix = "TransferUpdate";
            
            // Check if we're in a rapid update period
            if (IsRapidUpdatePeriod(zoneName))
            {
                var recentCount = GetRecentUpdateCount(zoneName);
                _logger.LogInformation(
                    "{Prefix}: Zone {Zone} is in rapid update period ({RecentCount} updates in last {Window}s), using rate-limited NOTIFY",
                    logPrefix, zoneName, recentCount, Constants.RapidUpdateWindowSeconds);
            }

            // Use rate-limited NOTIFY to prevent flooding slaves
            await SendNotifyToSlavesWithRateLimitAsync(zoneName, zoneConfig, notifySender, logPrefix, cancellationToken);

            _logger.LogInformation(
                "{Prefix}: Zone {Zone} serial {Serial} - history updated and slaves notified",
                logPrefix, zoneName, newSerial);
        }
        else
        {
            _logger.LogDebug("Zone {Zone} has no configured slaves, skipping NOTIFY", zoneName);
        }
    }

    /// <summary>
    /// Sends NOTIFY to all slaves with rate limiting to prevent flooding.
    /// Enforces minimum interval between NOTIFYs to give slaves time to process.
    /// </summary>
    private async Task SendNotifyToSlavesWithRateLimitAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        NotifySender notifySender,
        string logPrefix,
        CancellationToken cancellationToken)
    {
        var minIntervalMs = zoneConfig.MinSlaveNotifyIntervalMs ?? _config.Server.MinSlaveNotifyIntervalMs;

        // If rate limiting is disabled (0), send immediately
        if (minIntervalMs <= 0)
        {
            _logger.LogInformation("{Prefix}: Notifying all configured slaves for zone {Zone} (rate limiting disabled)",
                logPrefix, zoneName);
            await notifySender.NotifyAllAsync(zoneName, cancellationToken);
            _lastSlaveNotifyTime[zoneName] = DateTime.UtcNow;
            _logger.LogInformation("{Prefix}: All slaves notified for zone {Zone}",
                logPrefix, zoneName);
            return;
        }

        // Check if we need to wait before sending NOTIFY
        if (_lastSlaveNotifyTime.TryGetValue(zoneName, out var lastNotify))
        {
            var elapsed = DateTime.UtcNow - lastNotify;
            var elapsedMs = (int)elapsed.TotalMilliseconds;

            if (elapsedMs < minIntervalMs)
            {
                var waitMs = minIntervalMs - elapsedMs;
                _logger.LogDebug(
                    "{Prefix}: Delaying NOTIFY to slaves for zone {Zone} by {WaitMs}ms to prevent flooding (last NOTIFY: {ElapsedMs}ms ago, min interval: {MinIntervalMs}ms)",
                    logPrefix, zoneName, waitMs, elapsedMs, minIntervalMs);

                await Task.Delay(waitMs, cancellationToken);
            }
        }

        _logger.LogInformation("{Prefix}: Notifying all configured slaves for zone {Zone}",
            logPrefix, zoneName);
        
        await notifySender.NotifyAllAsync(zoneName, cancellationToken);
        _lastSlaveNotifyTime[zoneName] = DateTime.UtcNow;
        
        _logger.LogInformation("{Prefix}: All slaves notified for zone {Zone}",
            logPrefix, zoneName);
    }

    /// <summary>
    /// Records an update timestamp for rapid update detection.
    /// </summary>
    private void RecordUpdateTimestamp(string zoneName)
    {
        var now = DateTime.UtcNow;
        var timestamps = _recentUpdateTimestamps.GetOrAdd(zoneName, _ => new List<DateTime>());

        lock (timestamps)
        {
            timestamps.Add(now);

            // Prune old timestamps outside the tracking window
            var cutoff = now - TimeSpan.FromSeconds(Constants.RapidUpdateWindowSeconds);
            timestamps.RemoveAll(t => t < cutoff);
        }
    }

    /// <summary>
    /// Gets the number of recent updates within the rapid update tracking window.
    /// </summary>
    private int GetRecentUpdateCount(string zoneName)
    {
        if (!_recentUpdateTimestamps.TryGetValue(zoneName, out var timestamps))
            return 0;

        var cutoff = DateTime.UtcNow - TimeSpan.FromSeconds(Constants.RapidUpdateWindowSeconds);

        lock (timestamps)
        {
            return timestamps.Count(t => t >= cutoff);
        }
    }

    /// <summary>
    /// Checks if the zone is experiencing rapid updates.
    /// </summary>
    private bool IsRapidUpdatePeriod(string zoneName)
    {
        return GetRecentUpdateCount(zoneName) >= Constants.RapidUpdateThreshold;
    }

    /// <summary>
    /// Calculates the effective IXFR history depth, accounting for rapid updates.
    /// During rapid update periods, depth is increased to prevent version pruning
    /// before slaves can request intermediate versions.
    /// </summary>
    private int GetEffectiveHistoryDepth(string zoneName, ZoneConfig zoneConfig)
    {
        var baseDepth = zoneConfig.IxfrHistoryDepth ?? _config.Server.DefaultIxfrHistoryDepth;

        // If dynamic depth is disabled, return base depth
        if (!_config.Server.EnableDynamicHistoryDepth)
            return baseDepth;

        var recentUpdateCount = GetRecentUpdateCount(zoneName);

        // If we're in a rapid update period, increase depth
        if (recentUpdateCount >= Constants.RapidUpdateThreshold)
        {
            var dynamicDepth = baseDepth + Constants.RapidUpdateExtraHistoryDepth + recentUpdateCount;
            
            // Also respect max versions from security config
            var maxVersions = _config.Server.Security?.MaxZoneVersionsPerZone ?? 100;
            dynamicDepth = Math.Min(dynamicDepth, maxVersions);

            _logger.LogDebug(
                "Dynamic history depth for zone {Zone}: {BaseDepth} -> {DynamicDepth} (recent updates: {RecentCount})",
                zoneName, baseDepth, dynamicDepth, recentUpdateCount);

            return dynamicDepth;
        }

        return baseDepth;
    }

    private async Task UpdateZoneFromUpstreamAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        CancellationToken cancellationToken,
        bool triggeredByNotify = false)
    {
        // Get or create semaphore for this zone to serialize updates
        var semaphore = _zoneUpdateSemaphores.GetOrAdd(zoneName, _ => new SemaphoreSlim(1, 1));
        
        // Acquire semaphore to ensure only one update per zone at a time
        // Track whether we successfully acquired it to avoid releasing if we didn't
        bool semaphoreAcquired = false;
        try
        {
            await semaphore.WaitAsync(cancellationToken);
            semaphoreAcquired = true;
        }
        catch (OperationCanceledException)
        {
            // Semaphore was never acquired, don't release in finally
            throw;
        }
        
        var logPrefix = triggeredByNotify ? "NOTIFY-triggered" : "Poll";
        var timeout = GetUpstreamTimeout();
        var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
        
        try
        {
            _logger.LogInformation("{Prefix}: Checking zone {Zone} from upstream {Upstream}", 
                logPrefix, zoneName, zoneConfig.Upstream);

            // Check upstream for changes
            var upstreamSerial = await upstreamClient.GetSoaSerialAsync(zoneName, cancellationToken);
            var cachedSerial = _cache.GetSerial(zoneName);
            var cachedZoneCheck = _cache.GetZone(zoneName);

            // If cache is empty (after restart), always fetch to populate it
            // This prevents empty zones on slaves when they initiate transfers after receiving NOTIFY
            if (cachedSerial == null || cachedZoneCheck == null || cachedZoneCheck.Records.Count == 0)
            {
                _logger.LogInformation("{Prefix}: Zone {Zone} cache is empty or invalid, fetching from upstream (serial: {Serial})", 
                    logPrefix, zoneName, upstreamSerial);
                // Continue to fetch below
            }
            // If serial hasn't changed, skip the update but still notify slaves if this was triggered by NOTIFY
            // This ensures slaves are notified even if our serial check shows no change (handles race conditions)
            else if (cachedSerial == upstreamSerial)
            {
                _logger.LogInformation("{Prefix}: Zone {Zone} serial unchanged ({Serial}), no update needed", 
                    logPrefix, zoneName, upstreamSerial);
                
                // If triggered by NOTIFY, still send NOTIFY to slaves to ensure they check for updates
                // This handles cases where upstream sent NOTIFY but our serial check shows unchanged
                // This prevents empty zones on slaves when they initiate transfers after receiving NOTIFY
                if (triggeredByNotify)
                {
                    if (_notifySenders.TryGetValue(zoneName, out var notifySenderForUnchanged))
                    {
                        _logger.LogInformation("{Prefix}: Serial unchanged but NOTIFY received from upstream, notifying slaves for zone {Zone}", 
                            logPrefix, zoneName);
                        await notifySenderForUnchanged.NotifyAllAsync(zoneName, cancellationToken);
                        _logger.LogInformation("{Prefix}: Slaves notified for zone {Zone} (serial unchanged)", 
                            logPrefix, zoneName);
                    }
                }
                
                return;
            }

            // Serial changed or zone not cached - fetch and update
            _logger.LogInformation("{Prefix}: Zone {Zone} serial {OldSerial} -> {NewSerial}, fetching zone", 
                logPrefix, zoneName, cachedSerial ?? 0, upstreamSerial);

            // Fetch updated zone with retry logic for incomplete transfers
            var upstreamRecords = await FetchZoneWithValidationAsync(
                upstreamClient, 
                zoneName, 
                zoneConfig, 
                upstreamSerial,
                logPrefix,
                cancellationToken);
            
            if (upstreamRecords == null)
            {
                // Fetch failed after retries - keep existing cache and report failure
                _logger.LogWarning("{Prefix}: Zone {Zone} fetch failed after retries, keeping existing cache", 
                    logPrefix, zoneName);
                _selfRestartService.ReportZoneFailure(zoneName, "Zone fetch failed after retries");
                return;
            }
            
            // Validate we got records
            if (upstreamRecords.Count == 0)
            {
                _logger.LogWarning("{Prefix}: Zone {Zone} fetched from upstream but got empty records list, keeping existing cache", 
                    logPrefix, zoneName);
                return; // Don't update cache with empty data
            }
            
            // Calculate statistics for upstream records
            var upstreamStats = CalculateZoneStatistics(upstreamRecords, upstreamSerial);
            
            _logger.LogInformation(
                "{Prefix}: Zone {Zone} fetched from upstream {Upstream} | " +
                "Records: {RecordCount} | Serial: {Serial} | " +
                "RecordTypes: {RecordTypes} | SOA: Refresh={Refresh}s, Retry={Retry}s, Expire={Expire}s, Minimum={Minimum}s",
                logPrefix, zoneName, zoneConfig.Upstream, upstreamRecords.Count, upstreamSerial,
                upstreamStats.RecordTypeBreakdown, upstreamStats.Refresh, upstreamStats.Retry, 
                upstreamStats.Expire, upstreamStats.Minimum);

            // Apply filters
            var filteredRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneName);
            
            // Validate filtered records
            if (filteredRecords == null || filteredRecords.Count == 0)
            {
                _logger.LogWarning("{Prefix}: Zone {Zone} after filtering has no records, keeping existing cache", 
                    logPrefix, zoneName);
                _selfRestartService.ReportZoneFailure(zoneName, "Zone filtered to empty records");
                return; // Don't update cache with empty data
            }
            
            // Calculate statistics for filtered records
            var filteredStats = CalculateFilteredZoneStatistics(filteredRecords, upstreamSerial);
            
            _logger.LogInformation(
                "{Prefix}: Zone {Zone} filtered | " +
                "Records: {OriginalCount} -> {FilteredCount} | " +
                "RecordTypes: {RecordTypes} | " +
                "SOA: Serial={Serial}, Refresh={Refresh}s, Retry={Retry}s, Expire={Expire}s, Minimum={Minimum}s",
                logPrefix, zoneName, upstreamRecords.Count, filteredRecords.Count,
                filteredStats.RecordTypeBreakdown, filteredStats.Serial, filteredStats.Refresh,
                filteredStats.Retry, filteredStats.Expire, filteredStats.Minimum);

            // Save current cached version to history BEFORE updating cache
            // This ensures we have the previous version available for IXFR
            // CRITICAL: We save the complete zone version before replacing it, ensuring
            // we never lose version history and can always serve consistent zone versions
            var currentCachedZone = _cache.GetZone(zoneName);
            if (currentCachedZone != null && currentCachedZone.Serial != upstreamSerial)
            {
                await SaveCurrentVersionToHistoryAsync(zoneName, zoneConfig, currentCachedZone.Records, currentCachedZone.Serial);
            }

            // Update cache atomically - this replaces the entire zone, so concurrent reads get either old or new zone
            // CRITICAL: UpdateZone validates that all records belong to the same serial number
            // and replaces the entire zone atomically, preventing mixing of records from different versions
            _cache.UpdateZone(zoneName, filteredRecords);

            // Update zone history for IXFR support - add the new version
            await UpdateZoneHistoryAsync(zoneName, zoneConfig, filteredRecords, upstreamSerial);

            // Record this update for rapid update detection
            RecordUpdateTimestamp(zoneName);

            // Verify zone is fully cached and ready before sending NOTIFY
            // This prevents race conditions where NOTIFY is sent before zone is ready for IXFR
            var verifyZone = _cache.GetZone(zoneName);
            if (verifyZone == null || verifyZone.Records.Count == 0 || verifyZone.Serial != upstreamSerial)
            {
                _logger.LogWarning("{Prefix}: Zone {Zone} not ready after cache update (serial: {ExpectedSerial}, cached: {CachedSerial}, records: {RecordCount}), skipping NOTIFY", 
                    logPrefix, zoneName, upstreamSerial, verifyZone?.Serial ?? 0, verifyZone?.Records.Count ?? 0);
            }
            else
            {
                // Small delay to ensure zone is fully ready before sending NOTIFY
                // This gives time for any async operations to complete
                await Task.Delay(Constants.NotifyDelayMs, cancellationToken);

                // Send NOTIFY to all slaves with rate limiting
                if (_notifySenders.TryGetValue(zoneName, out var notifySender))
                {
                    // Check if we're in a rapid update period and log accordingly
                    if (IsRapidUpdatePeriod(zoneName))
                    {
                        var recentCount = GetRecentUpdateCount(zoneName);
                        _logger.LogInformation(
                            "{Prefix}: Zone {Zone} is in rapid update period ({RecentCount} updates in last {Window}s), using rate-limited NOTIFY",
                            logPrefix, zoneName, recentCount, Constants.RapidUpdateWindowSeconds);
                    }

                    // Use rate-limited NOTIFY to prevent flooding slaves
                    await SendNotifyToSlavesWithRateLimitAsync(zoneName, zoneConfig, notifySender, logPrefix, cancellationToken);

                    // Schedule slave verification if enabled
                    if (_verificationService != null && _zones.TryGetValue(zoneName, out var zoneEntry))
                    {
                        var verificationConfig = zoneEntry.Config;
                        var verificationEnabled = verificationConfig.SlaveVerificationEnabled ?? true; // Default to true
                        var verificationDelay = verificationConfig.SlaveVerificationDelay ?? 2; // Default to 2 seconds

                        if (verificationEnabled && verificationConfig.Slaves.Count > 0)
                        {
                            // Get serial and record count from cached zone
                            var cachedZone = _cache.GetZone(zoneName);
                            if (cachedZone != null)
                            {
                                var sentSerial = cachedZone.Serial;
                                var sentRecordCount = cachedZone.Records.Count;
                                var recordCountTolerance = verificationConfig.SlaveVerificationRecordCountTolerance ?? 0; // Default to 0
                                var clearHistoryOnMismatch = verificationConfig.ClearHistoryOnVerificationMismatch ?? true; // Default to true
                                var maxRetries = verificationConfig.MaxVerificationRetries ?? 3; // Default to 3

                                _logger.LogDebug(
                                    "{Prefix}: Scheduling slave verification for zone {Zone} (delay: {Delay}s, serial: {Serial}, records: {RecordCount}, tolerance: {Tolerance}, clearHistoryOnMismatch: {ClearHistory})",
                                    logPrefix, zoneName, verificationDelay, sentSerial, sentRecordCount, recordCountTolerance, clearHistoryOnMismatch);

                                _verificationService.ScheduleVerification(
                                    zoneName,
                                    sentSerial,
                                    sentRecordCount,
                                    verificationConfig.Slaves,
                                    verificationDelay,
                                    recordCountTolerance,
                                    notifySender,
                                    cancellationToken,
                                    clearHistoryCallback: ClearZoneHistory,
                                    clearHistoryOnMismatch: clearHistoryOnMismatch,
                                    maxRetries: maxRetries);
                            }
                            else
                            {
                                _logger.LogWarning(
                                    "{Prefix}: Cannot schedule verification for zone {Zone} - zone not found in cache",
                                    logPrefix, zoneName);
                            }
                        }
                    }
                }
                else
                {
                    _logger.LogWarning("{Prefix}: No slaves configured for zone {Zone}", 
                        logPrefix, zoneName);
                }
            }

            // Report successful zone update
            _selfRestartService.ReportZoneSuccess(zoneName);
            
            _logger.LogInformation("{Prefix}: Zone {Zone} update completed - cached and slaves notified", 
                logPrefix, zoneName);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown - log at debug level and rethrow
            _logger.LogDebug("{Prefix}: Zone {Zone} update cancelled during shutdown", 
                triggeredByNotify ? "NOTIFY-triggered" : "Poll", zoneName);
            throw;
        }
        catch (Exception ex)
        {
            // Only log non-cancellation errors and report failure
            if (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Error during {Prefix} update for zone {Zone}", 
                    triggeredByNotify ? "NOTIFY-triggered" : "poll", zoneName);
                _selfRestartService.ReportZoneFailure(zoneName, $"Zone update error: {ex.Message}");
            }
            else
            {
                _logger.LogDebug("{Prefix}: Zone {Zone} update error during shutdown: {Message}", 
                    triggeredByNotify ? "NOTIFY-triggered" : "Poll", zoneName, ex.Message);
            }
            throw;
        }
        finally
        {
            upstreamClient.Dispose();
            // Release semaphore only if we successfully acquired it
            if (semaphoreAcquired)
            {
                semaphore.Release();
            }
        }
    }

    private async Task PollUpstreamZoneOnceAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        CancellationToken cancellationToken)
    {
        await UpdateZoneFromUpstreamAsync(zoneName, zoneConfig, cancellationToken, triggeredByNotify: false);
    }

    private async Task PollUpstreamZoneAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        CancellationToken cancellationToken)
    {
        var pollIntervalSeconds = zoneConfig.PollInterval ?? _config.Server.UpstreamPollInterval;
        
        // If poll interval is 0 or less, polling is disabled - exit immediately
        if (pollIntervalSeconds <= 0)
        {
            _logger.LogInformation("Polling disabled for zone {Zone} (poll interval: {Interval}s)", 
                zoneName, pollIntervalSeconds);
            return;
        }
        
        var pollInterval = TimeSpan.FromSeconds(pollIntervalSeconds);
        var timeout = GetUpstreamTimeout();
        var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(pollInterval, cancellationToken);

                    // Check upstream for changes
                    var upstreamSerial = await upstreamClient.GetSoaSerialAsync(zoneName, cancellationToken);
                    var cachedSerial = _cache.GetSerial(zoneName);

                    if (cachedSerial == null || cachedSerial != upstreamSerial)
                    {
                        _logger.LogInformation("Poll: Zone {Zone} serial changed from {OldSerial} to {NewSerial}", 
                            zoneName, cachedSerial, upstreamSerial);

                        // Use shared update method
                        await UpdateZoneFromUpstreamAsync(zoneName, zoneConfig, cancellationToken, triggeredByNotify: false);
                    }
                }
                catch (OperationCanceledException)
                {
                    // Normal shutdown - exit gracefully
                    _logger.LogDebug("Polling task for zone {Zone} cancelled during shutdown", zoneName);
                    break;
                }
                catch (Exception ex)
                {
                    // Only log non-cancellation errors
                    if (!cancellationToken.IsCancellationRequested)
                    {
                        _logger.LogError(ex, "Error polling zone {Zone}", zoneName);
                    }
                    else
                    {
                        _logger.LogDebug("Error polling zone {Zone} during shutdown: {Message}", zoneName, ex.Message);
                    }
                }
            }
        }
        finally
        {
            upstreamClient.Dispose();
        }
    }

    /// <summary>
    /// Exports a filtered zone to BIND DNS format for debugging.
    /// </summary>
    /// <param name="zoneName">The zone name to export</param>
    /// <returns>BIND DNS format string, or null if zone not found</returns>
    public string? ExportZone(string zoneName)
    {
        var cachedZone = _cache.GetZone(zoneName);
        if (cachedZone == null)
        {
            return null;
        }

        return ZoneExporter.ExportToBindFormat(cachedZone, zoneName);
    }

    /// <summary>
    /// Exports a filtered zone to a file in BIND DNS format for debugging.
    /// </summary>
    /// <param name="zoneName">The zone name to export</param>
    /// <param name="filePath">The output file path</param>
    /// <returns>True if export was successful, false if zone not found</returns>
    public async Task<bool> ExportZoneToFileAsync(string zoneName, string filePath)
    {
        var cachedZone = _cache.GetZone(zoneName);
        if (cachedZone == null)
        {
            return false;
        }

        await ZoneExporter.ExportToFileAsync(cachedZone.Records, zoneName, filePath);
        return true;
    }

    /// <summary>
    /// Gets a list of all cached zone names.
    /// </summary>
    /// <returns>List of zone names</returns>
    public List<string> GetCachedZoneNames()
    {
        return _zones.Keys.ToList();
    }

    private ZoneStatistics CalculateZoneStatistics(List<DnsResourceRecord> records, uint serial)
    {
        var stats = new ZoneStatistics
        {
            RecordCount = records.Count,
            Serial = serial
        };

        // Count record types
        var typeCounts = new Dictionary<ResourceRecordType, int>();
        SoaRecord? soaRecord = null;

        foreach (var record in records)
        {
            if (record.RecordType == ResourceRecordType.SOA && record is SoaRecord soa)
            {
                soaRecord = soa;
            }

            if (!typeCounts.ContainsKey(record.RecordType))
            {
                typeCounts[record.RecordType] = 0;
            }
            typeCounts[record.RecordType]++;
        }

        // Build record type breakdown string
        var breakdown = new StringBuilder();
        foreach (var kvp in typeCounts.OrderByDescending(x => x.Value))
        {
            if (breakdown.Length > 0) breakdown.Append(", ");
            breakdown.Append($"{kvp.Key}:{kvp.Value}");
        }
        stats.RecordTypeBreakdown = breakdown.ToString();

        // Extract SOA details
        if (soaRecord != null)
        {
            stats.Refresh = soaRecord.Refresh;
            stats.Retry = soaRecord.Retry;
            stats.Expire = soaRecord.Expire;
            stats.Minimum = soaRecord.Minimum;
        }

        return stats;
    }

    private ZoneStatistics CalculateFilteredZoneStatistics(List<FilteredRecord> records, uint serial)
    {
        var stats = new ZoneStatistics
        {
            RecordCount = records.Count,
            Serial = serial
        };

        // Count record types
        var typeCounts = new Dictionary<ResourceRecordType, int>();
        SoaRecordData? soaData = null;

        foreach (var record in records)
        {
            if (record.RecordType == ResourceRecordType.SOA)
            {
                soaData = record.SoaData;
            }

            if (!typeCounts.ContainsKey(record.RecordType))
            {
                typeCounts[record.RecordType] = 0;
            }
            typeCounts[record.RecordType]++;
        }

        // Build record type breakdown string
        var breakdown = new StringBuilder();
        foreach (var kvp in typeCounts.OrderByDescending(x => x.Value))
        {
            if (breakdown.Length > 0) breakdown.Append(", ");
            breakdown.Append($"{kvp.Key}:{kvp.Value}");
        }
        stats.RecordTypeBreakdown = breakdown.ToString();

        // Extract SOA details
        if (soaData != null)
        {
            stats.Refresh = soaData.Refresh;
            stats.Retry = soaData.Retry;
            stats.Expire = soaData.Expire;
            stats.Minimum = soaData.Minimum;
        }

        return stats;
    }

    /// <summary>
    /// Loads zone histories from disk on startup.
    /// </summary>
    private async Task LoadZoneHistoriesAsync(CancellationToken cancellationToken)
    {
        if (_historyStorage == null)
        {
            _logger.LogDebug("History storage not configured, skipping history load");
            return;
        }

        _logger.LogInformation("Loading zone histories from disk...");

        foreach (var zoneName in _zones.Keys)
        {
            try
            {
                var history = await _historyStorage.LoadAsync(zoneName);
                if (history != null)
                {
                    _zoneHistories.AddOrUpdate(zoneName, history, (key, old) => history);
                    var availableSerials = history.GetAvailableSerials();
                    _logger.LogInformation(
                        "Loaded zone history for {ZoneName} ({VersionCount} versions) | " +
                        "Serials: [{Serials}] | Range: {OldestSerial}..{NewestSerial}",
                        zoneName, history.Count,
                        string.Join(", ", availableSerials),
                        history.GetOldestSerial() ?? 0,
                        history.GetNewestSerial() ?? 0);
                }
                else
                {
                    _logger.LogDebug("No history found for zone {ZoneName}, will create new history", zoneName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load history for zone {ZoneName}", zoneName);
            }
        }

        _logger.LogInformation("Zone history loading completed");
        
        // After initial zone poll, ensure current cached versions are in history
        // This handles the case where history was loaded but cache was populated after
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(Constants.CacheSyncDelayMs, cancellationToken); // Wait for initial poll to complete
                foreach (var zoneName in _zones.Keys)
                {
                    try
                    {
                        var cachedZone = _cache.GetZone(zoneName);
                        if (cachedZone != null && _zones.TryGetValue(zoneName, out var zoneEntry))
                        {
                            var history = GetZoneHistory(zoneName);
                            if (history != null && !history.HasVersion(cachedZone.Serial))
                            {
                                // Current cached version not in history - add it
                                history.AddVersion(cachedZone.Serial, cachedZone.Records);
                                if (_historyStorage != null)
                                {
                                    await _historyStorage.SaveAsync(history);
                                }
                                _logger.LogDebug("Added current cached version to history for {ZoneName} (serial: {Serial})",
                                    zoneName, cachedZone.Serial);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Failed to sync current cache to history for {ZoneName}", zoneName);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Cache sync task cancelled during shutdown");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error in background cache sync task");
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Saves the current cached version to history before it gets replaced.
    /// </summary>
    private async Task SaveCurrentVersionToHistoryAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        List<FilteredRecord> records,
        uint serial)
    {
        if (_historyStorage == null)
        {
            return; // History storage not configured
        }

        try
        {
            // Get or create history for this zone
            var history = _zoneHistories.GetOrAdd(zoneName, _ => new ZoneHistory(zoneName));

            // Add current version to history (if not already present)
            if (!history.HasVersion(serial))
            {
                history.AddVersion(serial, records);
                _logger.LogDebug("Saved current version to history for {ZoneName} (serial: {Serial})",
                    zoneName, serial);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to save current version to history for {ZoneName}", zoneName);
        }
    }

    /// <summary>
    /// Updates zone history when a zone is updated.
    /// </summary>
    private async Task UpdateZoneHistoryAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        List<FilteredRecord> filteredRecords,
        uint serial)
    {
        if (_historyStorage == null)
        {
            return; // History storage not configured
        }

        try
        {
            // Get or create history for this zone
            var history = _zoneHistories.GetOrAdd(zoneName, _ => new ZoneHistory(zoneName));

            // Add new version to history
            history.AddVersion(serial, filteredRecords);

            // Prune old versions based on effective depth (accounts for rapid updates)
            var historyDepth = GetEffectiveHistoryDepth(zoneName, zoneConfig);
            var prunedSerials = history.PruneOldVersions(historyDepth);
            
            // Delete zone files for pruned versions
            if (prunedSerials.Count > 0 && _historyStorage != null)
            {
                await DeleteZoneFilesForSerialsAsync(zoneName, prunedSerials);
            }
            
            if (prunedSerials.Count > 0)
            {
                _logger.LogDebug("Pruned {Count} old versions from history for {ZoneName} (kept {RemainingCount} versions)",
                    prunedSerials.Count, zoneName, history.Count);
            }

            // Save to disk synchronously to ensure history is persisted before IXFR requests can access it
            // This prevents race conditions where IXFR requests arrive before history is saved
            if (_historyStorage != null)
            {
                try
                {
                    await _historyStorage.SaveAsync(history);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to save zone history for {ZoneName}", zoneName);
                    // Continue execution - history is in memory even if disk save failed
                }
            }

            _logger.LogDebug("Updated zone history for {ZoneName} (serial: {Serial}, versions: {VersionCount})",
                zoneName, serial, history.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update zone history for {ZoneName}", zoneName);
        }
    }

    /// <summary>
    /// Gets zone history for a zone. Used by XferHandler.
    /// </summary>
    private ZoneHistory? GetZoneHistory(string zoneName)
    {
        return _zoneHistories.TryGetValue(zoneName, out var history) ? history : null;
    }

    /// <summary>
    /// Clears zone history to force AXFR on next transfer request.
    /// Called when verification detects a mismatch to ensure slaves get a full zone transfer.
    /// </summary>
    private void ClearZoneHistory(string zoneName)
    {
        _logger.LogWarning(
            "Clearing zone history for {Zone} to force AXFR fallback on next transfer request",
            zoneName);
        
        if (_zoneHistories.TryGetValue(zoneName, out var history))
        {
            var clearedVersions = history.Count;
            history.Clear();
            
            _logger.LogInformation(
                "Cleared {VersionCount} versions from history for zone {Zone} - next IXFR request will fall back to AXFR",
                clearedVersions, zoneName);
            
            // Also delete persisted history file if configured
            if (_historyStorage != null)
            {
                try
                {
                    // Save empty history to disk
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            await _historyStorage.SaveAsync(history);
                            _logger.LogDebug("Persisted cleared history for zone {Zone}", zoneName);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "Failed to persist cleared history for zone {Zone}", zoneName);
                        }
                    });
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Failed to clear persisted history for zone {Zone}", zoneName);
                }
            }
        }
        else
        {
            _logger.LogDebug("No history to clear for zone {Zone}", zoneName);
        }
    }

    /// <summary>
    /// Deletes zone files for the specified serial numbers.
    /// </summary>
    private async Task DeleteZoneFilesForSerialsAsync(string zoneName, List<uint> prunedSerials)
    {
        if (_historyStorage == null)
            return;

        foreach (var prunedSerial in prunedSerials)
        {
            try
            {
                var zoneFilePath = _historyStorage.GetZoneFilePath(zoneName, prunedSerial);
                if (File.Exists(zoneFilePath))
                {
                    File.Delete(zoneFilePath);
                    _logger.LogDebug("Deleted zone file for {ZoneName} serial {Serial}", zoneName, prunedSerial);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to delete zone file for {ZoneName} serial {Serial}",
                    zoneName, prunedSerial);
            }
        }

        await Task.CompletedTask;
    }

    /// <summary>
    /// Fetches a zone from upstream with validation and retry logic for incomplete transfers.
    /// </summary>
    private async Task<List<DnsResourceRecord>?> FetchZoneWithValidationAsync(
        UpstreamClient upstreamClient,
        string zoneName,
        ZoneConfig zoneConfig,
        uint upstreamSerial,
        string logPrefix,
        CancellationToken cancellationToken)
    {
        const int maxRetries = 3;
        const int defaultRecordCountThreshold = 50; // Default threshold for suspiciously small zones
        var recordCountThreshold = zoneConfig.UpstreamTransferRecordCountThreshold ?? defaultRecordCountThreshold;
        
        for (int attempt = 1; attempt <= maxRetries; attempt++)
        {
            var fetchStartTime = DateTime.UtcNow;
            _logger.LogDebug("{Prefix}: Initiating outbound AXFR for zone {Zone} from upstream {Upstream} (attempt {Attempt}/{MaxRetries})",
                logPrefix, zoneName, zoneConfig.Upstream, attempt, maxRetries);
            
            try
            {
                var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneName, cancellationToken);
                var fetchDuration = (DateTime.UtcNow - fetchStartTime).TotalMilliseconds;
                
                _logger.LogDebug(
                    "{Prefix}: Outbound AXFR completed: Zone={Zone} | Upstream={Upstream} | " +
                    "Records={RecordCount} | Duration={Duration}ms | Serial={Serial} | Attempt={Attempt}",
                    logPrefix, zoneName, zoneConfig.Upstream, upstreamRecords?.Count ?? 0, fetchDuration, upstreamSerial, attempt);
                
                // Validate we got records
                if (upstreamRecords == null || upstreamRecords.Count == 0)
                {
                    _logger.LogWarning("{Prefix}: Zone {Zone} fetched from upstream but got empty records list (attempt {Attempt})", 
                        logPrefix, zoneName, attempt);
                    if (attempt < maxRetries)
                    {
                        await Task.Delay(1000 * attempt, cancellationToken); // Exponential backoff
                        continue;
                    }
                    return null;
                }
                
                // Check if this looks like an "empty zone" (only SOA and NS records)
                var soaCount = upstreamRecords.Count(r => r.RecordType == ResourceRecordType.SOA);
                var nsCount = upstreamRecords.Count(r => r.RecordType == ResourceRecordType.NS);
                var otherRecordCount = upstreamRecords.Count - soaCount - nsCount;
                
                if (otherRecordCount == 0 && upstreamRecords.Count <= 3)
                {
                    _logger.LogWarning("{Prefix}: Zone {Zone} appears to be empty (only SOA/NS records: {RecordCount} total) (attempt {Attempt})", 
                        logPrefix, zoneName, upstreamRecords.Count, attempt);
                    
                    // Check if we have a previous version to compare against
                    var previousRecordCount = GetPreviousZoneRecordCount(zoneName);
                    if (previousRecordCount.HasValue && previousRecordCount.Value > 3)
                    {
                        _logger.LogWarning("{Prefix}: Zone {Zone} received empty zone but previous version had {PreviousCount} records, retrying...", 
                            logPrefix, zoneName, previousRecordCount.Value);
                        if (attempt < maxRetries)
                        {
                            await Task.Delay(1000 * attempt, cancellationToken); // Exponential backoff
                            continue;
                        }
                        // Last attempt failed - log but don't update cache
                        _logger.LogError("{Prefix}: Zone {Zone} still empty after {MaxRetries} attempts, keeping existing cache", 
                            logPrefix, zoneName, maxRetries);
                        return null;
                    }
                    // No previous version to compare - accept it (might be a new zone)
                    _logger.LogInformation("{Prefix}: Zone {Zone} appears empty but no previous version to compare, accepting", 
                        logPrefix, zoneName);
                    return upstreamRecords;
                }
                
                // Compare against previous version if available
                var previousCount = GetPreviousZoneRecordCount(zoneName);
                if (previousCount.HasValue)
                {
                    // Only check if we received FEWER records - more records is fine (zone might have grown)
                    if (upstreamRecords.Count < previousCount.Value)
                    {
                        var recordDifference = previousCount.Value - upstreamRecords.Count;
                        
                        // If we received significantly fewer records than before, this might be incomplete
                        if (recordDifference > recordCountThreshold)
                        {
                            _logger.LogWarning(
                                "{Prefix}: Zone {Zone} received suspiciously few records: {CurrentCount} (previous: {PreviousCount}, difference: {Difference}, threshold: {Threshold}) (attempt {Attempt})",
                                logPrefix, zoneName, upstreamRecords.Count, previousCount.Value, recordDifference, recordCountThreshold, attempt);
                            
                            if (attempt < maxRetries)
                            {
                                _logger.LogInformation("{Prefix}: Retrying zone transfer for {Zone} due to suspicious record count (received {CurrentCount}, expected ~{PreviousCount})", 
                                    logPrefix, zoneName, upstreamRecords.Count, previousCount.Value);
                                await Task.Delay(1000 * attempt, cancellationToken); // Exponential backoff
                                continue;
                            }
                            
                            // Last attempt - log warning but accept it (might be legitimate reduction)
                            _logger.LogWarning("{Prefix}: Zone {Zone} still has suspiciously few records after {MaxRetries} attempts ({CurrentCount} vs previous {PreviousCount}), accepting anyway", 
                                logPrefix, zoneName, maxRetries, upstreamRecords.Count, previousCount.Value);
                        }
                        else
                        {
                            // Fewer records but within threshold - might be legitimate reduction
                            _logger.LogInformation(
                                "{Prefix}: Zone {Zone} record count decreased: {PreviousCount} -> {CurrentCount} (difference: {Difference}, within threshold)",
                                logPrefix, zoneName, previousCount.Value, upstreamRecords.Count, recordDifference);
                        }
                    }
                    else if (upstreamRecords.Count > previousCount.Value)
                    {
                        // More records than before - this is fine, zone might have grown
                        var recordDifference = upstreamRecords.Count - previousCount.Value;
                        _logger.LogInformation(
                            "{Prefix}: Zone {Zone} record count increased: {PreviousCount} -> {CurrentCount} (difference: +{Difference})",
                            logPrefix, zoneName, previousCount.Value, upstreamRecords.Count, recordDifference);
                    }
                    else
                    {
                        // Same count - perfect
                        _logger.LogDebug(
                            "{Prefix}: Zone {Zone} record count unchanged: {RecordCount}",
                            logPrefix, zoneName, upstreamRecords.Count);
                    }
                }
                
                // Validation passed - return the records
                return upstreamRecords;
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("{Prefix}: Zone {Zone} fetch cancelled (attempt {Attempt}/{MaxRetries})", 
                    logPrefix, zoneName, attempt, maxRetries);
                
                if (attempt < maxRetries)
                {
                    await Task.Delay(1000 * attempt, cancellationToken); // Exponential backoff
                    continue;
                }
                
                _logger.LogError("{Prefix}: Zone {Zone} fetch cancelled after {MaxRetries} attempts", 
                    logPrefix, zoneName, maxRetries);
                return null;
            }
            catch (Exception ex)
            {
                // Check if this is an incomplete transfer error
                var isIncompleteTransfer = ex.Message.Contains("incomplete") || 
                                          ex.Message.Contains("missing SOA") ||
                                          ex.Message.Contains("aborted") ||
                                          ex.Message.Contains("cancelled") ||
                                          ex.Message.Contains("timed out");
                
                if (isIncompleteTransfer)
                {
                    _logger.LogWarning(ex, "{Prefix}: Zone {Zone} transfer incomplete/aborted (attempt {Attempt}/{MaxRetries}): {Message}", 
                        logPrefix, zoneName, attempt, maxRetries, ex.Message);
                }
                else
                {
                    _logger.LogWarning(ex, "{Prefix}: Zone {Zone} fetch failed (attempt {Attempt}/{MaxRetries}): {Message}", 
                        logPrefix, zoneName, attempt, maxRetries, ex.Message);
                }
                
                if (attempt < maxRetries)
                {
                    // For incomplete transfers, use longer backoff to give upstream time to recover
                    var backoffDelay = isIncompleteTransfer ? 2000 * attempt : 1000 * attempt;
                    _logger.LogInformation("{Prefix}: Retrying zone transfer for {Zone} in {Delay}ms (attempt {Attempt}/{MaxRetries})", 
                        logPrefix, zoneName, backoffDelay, attempt + 1, maxRetries);
                    await Task.Delay(backoffDelay, cancellationToken);
                    continue;
                }
                
                // Last attempt failed
                if (isIncompleteTransfer)
                {
                    _logger.LogError(ex, "{Prefix}: Zone {Zone} transfer incomplete/aborted after {MaxRetries} attempts - keeping existing cache", 
                        logPrefix, zoneName, maxRetries);
                }
                else
                {
                    _logger.LogError(ex, "{Prefix}: Zone {Zone} fetch failed after {MaxRetries} attempts", 
                        logPrefix, zoneName, maxRetries);
                }
                return null;
            }
        }
        
        return null;
    }
    
    /// <summary>
    /// Gets the upstream timeout from security configuration, or defaults to 600 seconds (10 minutes).
    /// </summary>
    private TimeSpan GetUpstreamTimeout()
    {
        var timeoutSeconds = _config.Server.Security?.ZoneTransferTimeoutSeconds ?? 600;
        return TimeSpan.FromSeconds(timeoutSeconds);
    }

    /// <summary>
    /// Gets the record count from the previous zone version (from cache or history).
    /// </summary>
    private int? GetPreviousZoneRecordCount(string zoneName)
    {
        // First check current cache
        var cachedZone = _cache.GetZone(zoneName);
        if (cachedZone != null && cachedZone.Records.Count > 0)
        {
            return cachedZone.Records.Count;
        }
        
        // Then check history for the most recent version
        if (_zoneHistories.TryGetValue(zoneName, out var history))
        {
            var newestSerial = history.GetNewestSerial();
            if (newestSerial.HasValue)
            {
                var version = history.GetVersion(newestSerial.Value);
                if (version != null && version.Records.Count > 0)
                {
                    return version.Records.Count;
                }
            }
        }
        
        return null;
    }

    /// <summary>
    /// Starts a background task to periodically clean up old zone history files.
    /// </summary>
    private async Task StartHistoryCleanupTaskAsync(CancellationToken cancellationToken)
    {
        var cleanupConfig = _config.Server.HistoryCleanup;
        if (cleanupConfig == null || !cleanupConfig.Enabled || _historyStorage == null)
        {
            _logger.LogDebug("History cleanup not configured or disabled, skipping cleanup task");
            return;
        }

        var interval = TimeSpan.FromSeconds(cleanupConfig.IntervalSeconds);
        var retentionDays = cleanupConfig.RetentionDays;

        _logger.LogInformation("Starting history cleanup task (interval: {Interval}s, retention: {RetentionDays} days)",
            cleanupConfig.IntervalSeconds, retentionDays);

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(interval, cancellationToken);
                
                try
                {
                    _historyStorage.CleanupOldZoneFiles(retentionDays);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during history cleanup");
                }
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("History cleanup task cancelled");
        }
    }

    public override void Dispose()
    {
        _xferHandler?.Stop();
        
        // Dispose all zone update semaphores
        foreach (var semaphore in _zoneUpdateSemaphores.Values)
        {
            semaphore.Dispose();
        }
        _zoneUpdateSemaphores.Clear();
        
        base.Dispose();
    }

    private class ZoneStatistics
    {
        public int RecordCount { get; set; }
        public uint Serial { get; set; }
        public string RecordTypeBreakdown { get; set; } = string.Empty;
        public uint Refresh { get; set; }
        public uint Retry { get; set; }
        public uint Expire { get; set; }
        public uint Minimum { get; set; }
    }
}

