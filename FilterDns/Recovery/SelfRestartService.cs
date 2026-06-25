using System.Collections.Concurrent;
using FilterDns.Config;
using Microsoft.Extensions.Logging;

namespace FilterDns.Recovery;

/// <summary>
/// Service that monitors for unrecoverable situations and triggers a self-restart.
/// When triggered, the service exits with a specific exit code, expecting the service
/// manager (systemd, supervisor, etc.) to restart the process.
/// </summary>
public class SelfRestartService
{
    private readonly SelfRestartConfig _config;
    private readonly ILogger<SelfRestartService> _logger;
    private readonly Action<int> _exitAction;
    private readonly Func<DateTime> _utcNow;
    private readonly Queue<DateTime> _restartAttempts;
    private readonly string? _restartHistoryFilePath;
    private readonly DateTime _startTime;
    private readonly ConcurrentDictionary<string, int> _zoneFailureCounts = new();
    private readonly ConcurrentDictionary<string, int> _verificationFailureCounts = new();
    private int _consecutiveGlobalFailures = 0;
    private bool _restartTriggered = false;
    private readonly object _restartLock = new();

    public SelfRestartService(
        SelfRestartConfig? config,
        ILogger<SelfRestartService> logger,
        Action<int>? exitAction = null,
        Func<DateTime>? utcNow = null,
        IEnumerable<DateTime>? existingRestartAttempts = null,
        string? restartHistoryFilePath = null)
    {
        _config = config ?? new SelfRestartConfig();
        _logger = logger;
        _exitAction = exitAction ?? Environment.Exit;
        _utcNow = utcNow ?? (() => DateTime.UtcNow);
        _restartHistoryFilePath = restartHistoryFilePath ?? Path.Combine(AppContext.BaseDirectory, "self-restart-history.txt");
        _restartAttempts = new Queue<DateTime>(existingRestartAttempts ?? LoadRestartAttempts(_restartHistoryFilePath));
        _startTime = _utcNow();

        if (_config.Enabled)
        {
            _logger.LogInformation(
                "Self-restart service initialized | " +
                "MaxConsecutiveZoneFailures={MaxZoneFailures} | " +
                "MaxVerificationFailuresPerZone={MaxVerificationFailures} | " +
                "MinimumUptime={MinimumUptime}s | " +
                "RestartExitCode={ExitCode}",
                _config.MaxConsecutiveZoneFailures,
                _config.MaxVerificationFailuresPerZone,
                _config.MinimumUptimeBeforeRestartSeconds,
                _config.RestartExitCode);
        }
        else
        {
            _logger.LogWarning("Self-restart service is DISABLED - unrecoverable situations will not trigger automatic restart");
        }
    }

    /// <summary>
    /// Reports a zone-related failure.
    /// </summary>
    public void ReportZoneFailure(string zoneName, string reason)
    {
        if (!_config.Enabled)
            return;

        var count = _zoneFailureCounts.AddOrUpdate(zoneName, 1, (_, c) => c + 1);
        Interlocked.Increment(ref _consecutiveGlobalFailures);

        _logger.LogWarning(
            "Zone failure reported: Zone={Zone} | Reason={Reason} | " +
            "ZoneFailureCount={ZoneCount} | GlobalFailureCount={GlobalCount}",
            zoneName, reason, count, _consecutiveGlobalFailures);

        CheckForRestart($"Zone {zoneName} failure: {reason}");
    }

    /// <summary>
    /// Reports a verification failure for a zone.
    /// </summary>
    public void ReportVerificationFailure(string zoneName, string slaveIp, string reason)
    {
        if (!_config.Enabled)
            return;

        var key = $"{zoneName}:{slaveIp}";
        var count = _verificationFailureCounts.AddOrUpdate(key, 1, (_, c) => c + 1);
        var zoneCount = _zoneFailureCounts.AddOrUpdate(zoneName, 1, (_, c) => c + 1);

        _logger.LogWarning(
            "Verification failure reported: Zone={Zone} | Slave={Slave} | Reason={Reason} | " +
            "SlaveFailureCount={SlaveCount} | ZoneFailureCount={ZoneCount}",
            zoneName, slaveIp, reason, count, zoneCount);

        if (zoneCount >= _config.MaxVerificationFailuresPerZone)
        {
            TriggerRestart($"Zone {zoneName} exceeded max verification failures ({zoneCount}/{_config.MaxVerificationFailuresPerZone})");
        }
    }

    /// <summary>
    /// Reports a critical error that should trigger immediate restart consideration.
    /// </summary>
    public void ReportCriticalError(string component, string reason)
    {
        if (!_config.Enabled)
            return;

        _logger.LogError(
            "CRITICAL ERROR reported: Component={Component} | Reason={Reason}",
            component, reason);

        Interlocked.Add(ref _consecutiveGlobalFailures, 3); // Critical errors count more
        CheckForRestart($"Critical error in {component}: {reason}");
    }

    /// <summary>
    /// Reports that a zone operation succeeded, resetting failure counts.
    /// </summary>
    public void ReportZoneSuccess(string zoneName)
    {
        if (!_config.Enabled)
            return;

        _zoneFailureCounts.TryRemove(zoneName, out _);
        
        // Reset verification failure counts for this zone
        var keysToRemove = _verificationFailureCounts.Keys
            .Where(k => k.StartsWith($"{zoneName}:"))
            .ToList();
        foreach (var key in keysToRemove)
        {
            _verificationFailureCounts.TryRemove(key, out _);
        }

        // If all zones are healthy, reset global counter
        if (_zoneFailureCounts.IsEmpty)
        {
            Interlocked.Exchange(ref _consecutiveGlobalFailures, 0);
        }
    }

    /// <summary>
    /// Checks if conditions for restart are met.
    /// </summary>
    private void CheckForRestart(string reason)
    {
        if (_consecutiveGlobalFailures >= _config.MaxConsecutiveZoneFailures)
        {
            TriggerRestart(reason);
        }
    }

    /// <summary>
    /// Triggers a self-restart of the service.
    /// </summary>
    public void TriggerRestart(string reason)
    {
        if (!_config.Enabled)
        {
            _logger.LogWarning(
                "Self-restart requested but disabled | Reason={Reason}",
                reason);
            return;
        }

        lock (_restartLock)
        {
            if (_restartTriggered)
            {
                _logger.LogDebug("Restart already triggered, ignoring duplicate request");
                return;
            }

            // Check minimum uptime
            var now = _utcNow();
            var uptime = (now - _startTime).TotalSeconds;
            if (uptime < _config.MinimumUptimeBeforeRestartSeconds)
            {
                _logger.LogWarning(
                    "Self-restart requested but minimum uptime not met | " +
                    "Uptime={Uptime}s | MinimumRequired={Minimum}s | Reason={Reason}",
                    uptime, _config.MinimumUptimeBeforeRestartSeconds, reason);
                return;
            }

            if (RestartWindowLimitReached(now))
            {
                _logger.LogError(
                    "Self-restart requested but restart window limit reached | MaxRestarts={MaxRestarts} | WindowSeconds={WindowSeconds} | Reason={Reason}",
                    _config.MaxRestartsInWindow, _config.RestartWindowSeconds, reason);
                return;
            }

            _restartAttempts.Enqueue(now);
            SaveRestartAttempts();
            _restartTriggered = true;

            _logger.LogError(
                "TRIGGERING SELF-RESTART | Reason={Reason} | " +
                "Uptime={Uptime}s | ExitCode={ExitCode} | DelaySeconds={Delay}",
                reason, uptime, _config.RestartExitCode, _config.RestartDelaySeconds);

            // Trigger restart in background to allow current operation to complete
            _ = Task.Run(async () =>
            {
                try
                {
                    // Wait for configured delay to allow logs to flush
                    await Task.Delay(TimeSpan.FromSeconds(_config.RestartDelaySeconds));

                    _logger.LogError(
                        "EXITING FOR RESTART | ExitCode={ExitCode}",
                        _config.RestartExitCode);

                    // Exit with specific code - service manager should restart us
                    _exitAction(_config.RestartExitCode);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during self-restart sequence");
                    // Force exit anyway
                    _exitAction(_config.RestartExitCode);
                }
            });
        }
    }

    private bool RestartWindowLimitReached(DateTime now)
    {
        if (_config.MaxRestartsInWindow <= 0)
        {
            return false;
        }

        var cutoff = now.AddSeconds(-_config.RestartWindowSeconds);
        while (_restartAttempts.Count > 0 && _restartAttempts.Peek() < cutoff)
        {
            _restartAttempts.Dequeue();
        }

        return _restartAttempts.Count >= _config.MaxRestartsInWindow;
    }

    private static IEnumerable<DateTime> LoadRestartAttempts(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return [];
        }

        try
        {
            return File.ReadAllLines(path)
                .Select(line => DateTime.TryParse(line, null, System.Globalization.DateTimeStyles.RoundtripKind, out var timestamp)
                    ? timestamp
                    : (DateTime?)null)
                .Where(timestamp => timestamp.HasValue)
                .Select(timestamp => timestamp!.Value)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private void SaveRestartAttempts()
    {
        if (string.IsNullOrWhiteSpace(_restartHistoryFilePath))
        {
            return;
        }

        try
        {
            File.WriteAllLines(_restartHistoryFilePath, _restartAttempts.Select(timestamp => timestamp.ToString("O")));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist self-restart history to {Path}", _restartHistoryFilePath);
        }
    }

    /// <summary>
    /// Gets current failure statistics.
    /// </summary>
    public (int GlobalFailures, int ZonesWithFailures, TimeSpan Uptime) GetStats()
    {
        return (
            _consecutiveGlobalFailures,
            _zoneFailureCounts.Count,
            _utcNow() - _startTime
        );
    }

    /// <summary>
    /// Checks if restart has been triggered.
    /// </summary>
    public bool IsRestartTriggered => _restartTriggered;
}
