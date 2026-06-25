namespace FilterDns;

/// <summary>
/// Application-wide constants for timing, delays, and configuration values.
/// </summary>
public static class Constants
{
    /// <summary>
    /// Delay in milliseconds before sending NOTIFY to slaves after zone update.
    /// This ensures zone is fully ready before slaves initiate transfers.
    /// </summary>
    public const int NotifyDelayMs = 100;

    /// <summary>
    /// Delay in milliseconds before closing TCP connection after zone transfer completes.
    /// This allows the client to finish reading all zone transfer data.
    /// </summary>
    public const int TcpCloseDelayMs = 200;

    /// <summary>
    /// Delay in milliseconds before syncing cache to history after initial zone poll.
    /// This ensures initial poll completes before sync operation.
    /// </summary>
    public const int CacheSyncDelayMs = 5000;

    /// <summary>
    /// Timeout in seconds for waiting for NOTIFY response from slave servers.
    /// </summary>
    public const int NotifyTimeoutSeconds = 5;

    /// <summary>
    /// Maximum valid UDP/TCP port number.
    /// </summary>
    public const int MaxPort = 65535;

    // === RAPID UPDATE HANDLING CONSTANTS ===

    /// <summary>
    /// Default debounce time in milliseconds for NOTIFY processing.
    /// When multiple NOTIFYs arrive rapidly, wait this long for quiet period before processing.
    /// This prevents cascade of updates during rapid zone changes on master.
    /// </summary>
    public const int DefaultNotifyDebounceMs = 500;

    /// <summary>
    /// Default minimum interval in milliseconds between sending NOTIFYs to slaves.
    /// This prevents flooding slaves with too many NOTIFYs during rapid updates.
    /// </summary>
    public const int DefaultMinSlaveNotifyIntervalMs = 2000;

    /// <summary>
    /// Time window in seconds for tracking rapid updates.
    /// Used to detect when zone is experiencing rapid updates and adjust behavior accordingly.
    /// </summary>
    public const int RapidUpdateWindowSeconds = 300; // 5 minutes

    /// <summary>
    /// Threshold for number of updates in the rapid update window to trigger enhanced handling.
    /// When more than this many updates occur within RapidUpdateWindowSeconds, 
    /// dynamic history depth expansion is activated.
    /// </summary>
    public const int RapidUpdateThreshold = 5;

    /// <summary>
    /// Extra history versions to keep during rapid update periods.
    /// Added on top of configured IxfrHistoryDepth when rapid updates are detected.
    /// </summary>
    public const int RapidUpdateExtraHistoryDepth = 10;

    /// <summary>
    /// Maximum debounce time in milliseconds to prevent updates from being delayed too long.
    /// </summary>
    public const int MaxNotifyDebounceMs = 5000;
}
