using System.Net;

namespace FilterDns.Config;

public class AppConfiguration
{
    public ServerConfig Server { get; set; } = new();
    public List<ZoneConfig> Zones { get; set; } = new();
}

public class ServerConfig
{
    public string ListenAddress { get; set; } = "0.0.0.0";
    public int ListenPort { get; set; } = 53;
    public string LogLevel { get; set; } = "Information"; // Deprecated: Use Logging.DefaultLevel instead. Kept for backward compatibility.
    public int UpstreamPollInterval { get; set; } = 300;
    public SeqConfig? Seq { get; set; }
    public List<string> HealthCheckAcl { get; set; } = new();
    public string? DataDirectory { get; set; } // Default: "./data"
    public int DefaultIxfrHistoryDepth { get; set; } = 20; // Default retention for IXFR history
    public bool ExportBindZoneFiles { get; set; } = true; // Export zone versions as BIND format files (default: true)
    public HistoryCleanupConfig? HistoryCleanup { get; set; } // Optional: cleanup configuration for zone history files
    public LoggingConfig? Logging { get; set; } // Optional: granular logging configuration
    public EmailConfig? Email { get; set; } // Optional: email alert configuration
    /// <summary>
    /// IXFR response mode. Controls how IXFR requests are handled.
    /// - Incremental: Send incremental changes (RFC 1995 compliant IXFR response)
    /// - FullZone: Always send full zone transfer in response to IXFR requests (fallback to AXFR format)
    /// Default: Incremental
    /// </summary>
    public string IxfrResponseMode { get; set; } = "Incremental"; // "Incremental" or "FullZone"
    public SecurityConfig? Security { get; set; } // Optional: security hardening configuration
    public SelfRestartConfig? SelfRestart { get; set; } // Optional: self-restart configuration for recovery

    // === RAPID UPDATE HANDLING CONFIGURATION ===

    /// <summary>
    /// Debounce time in milliseconds for NOTIFY processing.
    /// When multiple NOTIFYs arrive from upstream master rapidly, wait this long for a quiet period before processing.
    /// This coalesces rapid updates and prevents cascade of zone fetches.
    /// Set to 0 to disable debouncing (process each NOTIFY immediately).
    /// Default: 500ms
    /// </summary>
    public int NotifyDebounceMs { get; set; } = 500;

    /// <summary>
    /// Minimum interval in milliseconds between sending NOTIFYs to slaves.
    /// Prevents flooding slaves with too many NOTIFYs during rapid updates.
    /// Set to 0 to disable (send NOTIFYs immediately after each update).
    /// Default: 2000ms (2 seconds)
    /// </summary>
    public int MinSlaveNotifyIntervalMs { get; set; } = 2000;

    /// <summary>
    /// Enable dynamic history depth expansion during rapid update periods.
    /// When enabled, IXFR history depth is automatically increased when rapid updates are detected,
    /// preventing version pruning before slaves can request intermediate versions.
    /// Default: true
    /// </summary>
    public bool EnableDynamicHistoryDepth { get; set; } = true;
}

/// <summary>
/// Configuration for automatic self-restart on unrecoverable situations.
/// When enabled, the service will exit (expecting systemd/supervisor to restart it).
/// </summary>
public class SelfRestartConfig
{
    /// <summary>
    /// Enable automatic self-restart on unrecoverable situations.
    /// The service exits with a specific code, expecting the service manager to restart it.
    /// Default: true
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Exit code to use when triggering a self-restart.
    /// Default: 100 (to distinguish from normal exit 0 and error exit 1)
    /// </summary>
    public int RestartExitCode { get; set; } = 100;

    /// <summary>
    /// Number of consecutive zone failures across all zones before triggering restart.
    /// Default: 5
    /// </summary>
    public int MaxConsecutiveZoneFailures { get; set; } = 5;

    /// <summary>
    /// Number of verification failures for a single zone before triggering restart.
    /// Default: 5 (after MaxVerificationRetries * slaves count)
    /// </summary>
    public int MaxVerificationFailuresPerZone { get; set; } = 5;

    /// <summary>
    /// Delay in seconds before triggering restart (allows logs to flush).
    /// Default: 5
    /// </summary>
    public int RestartDelaySeconds { get; set; } = 5;

    /// <summary>
    /// Minimum uptime in seconds before a restart is allowed.
    /// Prevents restart loops.
    /// Default: 300 (5 minutes)
    /// </summary>
    public int MinimumUptimeBeforeRestartSeconds { get; set; } = 300;

    /// <summary>
    /// Maximum number of restarts within the time window before giving up.
    /// Set to 0 to disable restart limiting.
    /// Default: 3
    /// </summary>
    public int MaxRestartsInWindow { get; set; } = 3;

    /// <summary>
    /// Time window in seconds for counting restarts.
    /// Default: 3600 (1 hour)
    /// </summary>
    public int RestartWindowSeconds { get; set; } = 3600;
}

public class HistoryCleanupConfig
{
    public bool Enabled { get; set; } = true; // Enable cleanup
    public int IntervalSeconds { get; set; } = 3600; // Run cleanup every hour (default)
    public int RetentionDays { get; set; } = 7; // Keep zone files for 7 days (default)
}

public class SeqConfig
{
    public string? ServerUrl { get; set; }
    public string? ApiKey { get; set; }
    public bool Enabled { get; set; } = false;
}

/// <summary>
/// Granular logging configuration for different components and operations.
/// Allows separate control of regular operations logging vs debug logging.
/// </summary>
public class LoggingConfig
{
    /// <summary>
    /// Default log level for all components. Used when no specific category override is set.
    /// Valid values: Trace, Debug, Information, Warning, Error, Critical, None
    /// Default: Information
    /// </summary>
    public string DefaultLevel { get; set; } = "Information";

    /// <summary>
    /// Log level for regular operations (zone transfers, NOTIFY, polling, etc.)
    /// These are typically Information-level logs that track normal system operation.
    /// Valid values: Trace, Debug, Information, Warning, Error, Critical, None
    /// Default: Information
    /// </summary>
    public string OperationsLevel { get; set; } = "Information";

    /// <summary>
    /// Log level for debug/troubleshooting information (connection details, query details, etc.)
    /// These are typically Debug-level logs with detailed diagnostic information.
    /// Valid values: Trace, Debug, Information, Warning, Error, Critical, None
    /// Default: Debug
    /// </summary>
    public string DebugLevel { get; set; } = "Debug";

    /// <summary>
    /// Per-category log level overrides. Key is the namespace/logger name (e.g., "FilterDns.Proxy", "FilterDns.Xfer").
    /// Valid values: Trace, Debug, Information, Warning, Error, Critical, None
    /// If not specified, uses DefaultLevel.
    /// </summary>
    public Dictionary<string, string> Categories { get; set; } = new();
}

public class ZoneConfig
{
    public string Name { get; set; } = string.Empty;
    public string Upstream { get; set; } = string.Empty;
    public bool CacheEnabled { get; set; } = true;
    public int? PollInterval { get; set; }
    public string Ns1 { get; set; } = string.Empty; // Required: Master NS (for SOA)
    public string Ns2 { get; set; } = string.Empty; // Required
    public string? Ns3 { get; set; } // Optional
    public string? Ns4 { get; set; } // Optional
    public string? SoaRname { get; set; } // Optional: if not provided, original rname is preserved
    public bool FilterPrivateIPs { get; set; } = false; // Optional: filter out A/AAAA records with private IPs
    public List<string> PrivateIPRanges { get; set; } = new(); // Optional: custom private IP ranges (CIDR notation). If empty, uses default RFC 1918 ranges
    public List<SlaveConfig> Slaves { get; set; } = new();
    public List<string> XferWhitelist { get; set; } = new();
    public bool? SlaveVerificationEnabled { get; set; } // Optional: defaults to true if not specified
    public int? SlaveVerificationDelay { get; set; } // Optional: defaults to 2 seconds if not specified
    public int? SlaveVerificationRecordCountTolerance { get; set; } // Optional: acceptable difference in record count, defaults to 0
    public int? IxfrHistoryDepth { get; set; } // Optional: per-zone override for IXFR history retention
    public int? UpstreamTransferRecordCountThreshold { get; set; } // Optional: threshold for detecting incomplete transfers (default: 50). If received record count is this many fewer than previous, retry transfer.
    
    // === RELIABILITY CONFIGURATION ===
    
    /// <summary>
    /// When slave verification fails (mismatch detected), clear zone history to force AXFR on next request.
    /// This ensures slaves always get a full zone transfer after a mismatch, preventing repeated IXFR failures.
    /// Default: true (recommended for maximum reliability)
    /// </summary>
    public bool? ClearHistoryOnVerificationMismatch { get; set; }
    
    /// <summary>
    /// Minimum number of records a zone must have to be served to slaves.
    /// Zone transfers are refused if the zone has fewer records than this threshold.
    /// Set to 0 to disable this check.
    /// Default: 3 (SOA + at least 2 NS records)
    /// </summary>
    public int? MinimumZoneRecordCount { get; set; }
    
    /// <summary>
    /// Threshold for detecting suspicious IXFR diffs (as a percentage of current zone size).
    /// If IXFR would delete more than this percentage of records, force AXFR fallback.
    /// Set to 100 to disable this check.
    /// Default: 50 (50% of records)
    /// </summary>
    public int? IxfrSuspiciousDeletionThreshold { get; set; }
    
    /// <summary>
    /// Maximum number of times to retry verification before giving up.
    /// After this many failed verifications, the zone is marked as unhealthy.
    /// Default: 3
    /// </summary>
    public int? MaxVerificationRetries { get; set; }

    // === RAPID UPDATE HANDLING (PER-ZONE OVERRIDES) ===

    /// <summary>
    /// Per-zone override for NOTIFY debounce time in milliseconds.
    /// When multiple NOTIFYs arrive from upstream master rapidly, wait this long for a quiet period before processing.
    /// Set to 0 to disable debouncing for this zone.
    /// If not specified, uses Server.NotifyDebounceMs (default: 500ms)
    /// </summary>
    public int? NotifyDebounceMs { get; set; }

    /// <summary>
    /// Per-zone override for minimum interval between sending NOTIFYs to slaves in milliseconds.
    /// Set to 0 to disable for this zone.
    /// If not specified, uses Server.MinSlaveNotifyIntervalMs (default: 2000ms)
    /// </summary>
    public int? MinSlaveNotifyIntervalMs { get; set; }
}

public class SlaveConfig
{
    public string Ip { get; set; } = string.Empty;
    public int Port { get; set; } = 53;

    /// <summary>
    /// Gets the parsed IP address, or null if invalid.
    /// </summary>
    public IPAddress? GetIpAddress()
    {
        if (string.IsNullOrWhiteSpace(Ip))
            return null;
        
        if (IPAddress.TryParse(Ip, out var ipAddress))
        {
            // Reject broadcast and none addresses
            if (ipAddress.Equals(IPAddress.Broadcast) || ipAddress.Equals(IPAddress.None))
                return null;
            
            return ipAddress;
        }
        
        return null;
    }

    /// <summary>
    /// Checks if this slave configuration is valid.
    /// </summary>
    public bool IsValid()
    {
        return GetIpAddress() != null && Port > 0 && Port <= 65535;
    }
}

/// <summary>
/// Email alert configuration for sending notifications about errors and verification issues.
/// </summary>
public class EmailConfig
{
    /// <summary>
    /// Enable email alerts. Default: false
    /// </summary>
    public bool Enabled { get; set; } = false;

    /// <summary>
    /// SMTP server hostname or IP address. Required if Enabled is true.
    /// </summary>
    public string SmtpServer { get; set; } = string.Empty;

    /// <summary>
    /// SMTP server port. Default: 25 (unencrypted) or 587 (if SSL/StartTLS enabled)
    /// </summary>
    public int SmtpPort { get; set; } = 25;

    /// <summary>
    /// Enable SSL/TLS encryption. Default: false (unencrypted)
    /// </summary>
    public bool EnableSsl { get; set; } = false;

    /// <summary>
    /// Enable StartTLS. Note: EnableSsl handles both SSL and StartTLS in .NET.
    /// Default: false (unencrypted)
    /// </summary>
    public bool EnableStartTls { get; set; } = false;

    /// <summary>
    /// SMTP username for authentication. Leave empty for unauthenticated SMTP (default).
    /// </summary>
    public string? Username { get; set; }

    /// <summary>
    /// SMTP password for authentication. Leave empty for unauthenticated SMTP (default).
    /// </summary>
    public string? Password { get; set; }

    /// <summary>
    /// From email address. Required if Enabled is true.
    /// </summary>
    public string FromAddress { get; set; } = string.Empty;

    /// <summary>
    /// From display name. Optional.
    /// </summary>
    public string? FromName { get; set; }

    /// <summary>
    /// To email address(es). Multiple addresses can be comma-separated. Required if Enabled is true.
    /// </summary>
    public string ToAddress { get; set; } = string.Empty;

    /// <summary>
    /// CC email address(es). Multiple addresses can be comma-separated. Optional.
    /// </summary>
    public string? CcAddress { get; set; }

    /// <summary>
    /// BCC email address(es). Multiple addresses can be comma-separated. Optional.
    /// </summary>
    public string? BccAddress { get; set; }

    /// <summary>
    /// SMTP timeout in seconds. Default: 30
    /// </summary>
    public int TimeoutSeconds { get; set; } = 30;
}

/// <summary>
/// Security hardening configuration for DNS parser and file operations.
/// Provides configurable limits and a master switch to enable/disable security hardening.
/// </summary>
public class SecurityConfig
{
    /// <summary>
    /// Master switch to enable/disable security hardening features.
    /// When disabled, security checks are bypassed (not recommended for production).
    /// Default: true (hardening enabled)
    /// </summary>
    public bool SecurityHardeningEnabled { get; set; } = true;

    /// <summary>
    /// Maximum compression pointer depth for DNS name compression (RFC 1035).
    /// Prevents infinite loops from malicious compression pointers.
    /// Default: 10 (RFC 1035 recommendation)
    /// </summary>
    public int MaxCompressionPointerDepth { get; set; } = 10;

    /// <summary>
    /// Maximum domain name length in bytes (RFC 1035).
    /// Default: 255 bytes
    /// </summary>
    public int MaxDomainNameLength { get; set; } = 255;

    /// <summary>
    /// Maximum label length in bytes (RFC 1035).
    /// Default: 63 bytes
    /// </summary>
    public int MaxLabelLength { get; set; } = 63;

    /// <summary>
    /// Maximum count for DNS message sections (questions, answers, authority, additional).
    /// Prevents DoS from excessive counts.
    /// Default: 100
    /// </summary>
    public int MaxMessageCounts { get; set; } = 100;

    /// <summary>
    /// Maximum zone name length in characters.
    /// Default: 253 characters (RFC 1035)
    /// </summary>
    public int MaxZoneNameLength { get; set; } = 253;

    /// <summary>
    /// Enable symlink protection in file operations.
    /// When enabled, symlinks in data directory are rejected.
    /// Default: true
    /// </summary>
    public bool EnableSymlinkProtection { get; set; } = true;

    /// <summary>
    /// Maximum RDATA length in bytes for DNS resource records.
    /// Prevents DoS from excessively large RDATA fields.
    /// Default: 65535 (maximum allowed by DNS protocol)
    /// </summary>
    public int MaxRdataLength { get; set; } = 65535;

    /// <summary>
    /// Maximum concurrent TCP connections for zone transfers.
    /// Prevents DoS from connection exhaustion.
    /// Default: 100
    /// </summary>
    public int MaxConcurrentTcpConnections { get; set; } = 100;

    /// <summary>
    /// Maximum concurrent UDP requests (NOTIFY, queries).
    /// Prevents DoS from request flooding.
    /// Default: 200
    /// </summary>
    public int MaxConcurrentUdpRequests { get; set; } = 200;

    /// <summary>
    /// Maximum connections per IP address.
    /// Prevents single IP from exhausting connection pool.
    /// Default: 10
    /// </summary>
    public int MaxConnectionsPerIp { get; set; } = 10;

    /// <summary>
    /// TCP connection timeout in seconds.
    /// Connections idle longer than this are closed.
    /// Default: 300 (5 minutes)
    /// </summary>
    public int TcpConnectionTimeoutSeconds { get; set; } = 300;

    /// <summary>
    /// Zone transfer timeout in seconds.
    /// Zone transfers taking longer than this are aborted.
    /// Default: 600 (10 minutes)
    /// </summary>
    public int ZoneTransferTimeoutSeconds { get; set; } = 600;

    /// <summary>
    /// Maximum zone transfer size in bytes.
    /// Prevents DoS from excessively large zone transfers.
    /// Default: 10485760 (10MB)
    /// </summary>
    public long MaxZoneTransferSizeBytes { get; set; } = 10485760;

    /// <summary>
    /// Maximum zone history file size in bytes.
    /// Prevents disk space exhaustion from large history files.
    /// Default: 104857600 (100MB)
    /// </summary>
    public long MaxZoneHistoryFileSizeBytes { get; set; } = 104857600;

    /// <summary>
    /// Maximum number of zone versions to keep per zone.
    /// Prevents unlimited version accumulation.
    /// Default: 100
    /// </summary>
    public int MaxZoneVersionsPerZone { get; set; } = 100;

    /// <summary>
    /// Enable cache integrity checks using SHA-256 hashes.
    /// When enabled, zone versions are hashed and validated on load.
    /// Default: true
    /// </summary>
    public bool EnableCacheIntegrityChecks { get; set; } = true;

    /// <summary>
    /// Enable audit logging for security events.
    /// When enabled, security-relevant events are logged.
    /// Default: true
    /// </summary>
    public bool EnableAuditLogging { get; set; } = true;

    /// <summary>
    /// Audit log failed zone transfer attempts.
    /// Default: true
    /// </summary>
    public bool AuditLogFailedTransfers { get; set; } = true;

    /// <summary>
    /// Audit log NOTIFY messages from unauthorized sources.
    /// Default: true
    /// </summary>
    public bool AuditLogUnauthorizedNotify { get; set; } = true;

    /// <summary>
    /// Audit log health check queries.
    /// Default: true
    /// </summary>
    public bool AuditLogHealthCheckQueries { get; set; } = true;

    /// <summary>
    /// Audit log configuration file changes.
    /// Default: true
    /// </summary>
    public bool AuditLogConfigChanges { get; set; } = true;
}

