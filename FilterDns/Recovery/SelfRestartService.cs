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
    private readonly DateTime _startTime;
    private readonly ConcurrentDictionary<string, int> _zoneFailureCounts = new();
    private readonly ConcurrentDictionary<string, int> _verificationFailureCounts = new();
    private int _consecutiveGlobalFailures = 0;
    private bool _restartTriggered = false;
    private readonly object _restartLock = new();

    public SelfRestartService(SelfRestartConfig? config, ILogger<SelfRestartService> logger)
    {
        _config = config ?? new SelfRestartConfig();
        _logger = logger;
        _startTime = DateTime.UtcNow;

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
            var uptime = (DateTime.UtcNow - _startTime).TotalSeconds;
            if (uptime < _config.MinimumUptimeBeforeRestartSeconds)
            {
                _logger.LogWarning(
                    "Self-restart requested but minimum uptime not met | " +
                    "Uptime={Uptime}s | MinimumRequired={Minimum}s | Reason={Reason}",
                    uptime, _config.MinimumUptimeBeforeRestartSeconds, reason);
                return;
            }

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
                    Environment.Exit(_config.RestartExitCode);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during self-restart sequence");
                    // Force exit anyway
                    Environment.Exit(_config.RestartExitCode);
                }
            });
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
            DateTime.UtcNow - _startTime
        );
    }

    /// <summary>
    /// Checks if restart has been triggered.
    /// </summary>
    public bool IsRestartTriggered => _restartTriggered;
}
