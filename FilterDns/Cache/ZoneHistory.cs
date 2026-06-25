using System.Collections.Concurrent;
using FilterDns.Filter;

namespace FilterDns.Cache;

/// <summary>
/// Represents a single version of a zone at a specific serial number.
/// </summary>
public class ZoneVersion
{
    public uint Serial { get; set; }
    public List<FilteredRecord> Records { get; set; } = new();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Manages zone version history for a single zone.
/// Stores multiple versions keyed by serial number for IXFR support.
/// </summary>
public class ZoneHistory
{
    private readonly ConcurrentDictionary<uint, ZoneVersion> _versions = new();

    /// <summary>
    /// Gets the zone name this history belongs to.
    /// </summary>
    public string ZoneName { get; }

    public ZoneHistory(string zoneName)
    {
        ZoneName = zoneName ?? throw new ArgumentNullException(nameof(zoneName));
    }

    /// <summary>
    /// Adds a new zone version to the history.
    /// </summary>
    public void AddVersion(uint serial, List<FilteredRecord> records)
    {
        if (records == null)
            throw new ArgumentNullException(nameof(records));

        var version = new ZoneVersion
        {
            Serial = serial,
            Records = new List<FilteredRecord>(records), // Defensive copy
            Timestamp = DateTime.UtcNow
        };

        _versions.AddOrUpdate(serial, version, (key, old) => version);
    }

    /// <summary>
    /// Gets a specific zone version by serial number.
    /// Returns null if the version doesn't exist.
    /// </summary>
    public ZoneVersion? GetVersion(uint serial)
    {
        return _versions.TryGetValue(serial, out var version) ? version : null;
    }

    /// <summary>
    /// Gets all versions between two serial numbers (inclusive).
    /// Returns versions ordered by serial number (ascending).
    /// </summary>
    public List<ZoneVersion> GetVersionsBetween(uint fromSerial, uint toSerial)
    {
        var result = new List<ZoneVersion>();

        // Handle serial wraparound (uint32 max = 4294967295)
        if (fromSerial > toSerial)
        {
            // Wraparound case: fromSerial is after wraparound
            // Get versions from fromSerial to uint.MaxValue, then from 0 to toSerial
            foreach (var kvp in _versions.Where(v => v.Key >= fromSerial).OrderBy(v => v.Key))
            {
                result.Add(kvp.Value);
            }
            foreach (var kvp in _versions.Where(v => v.Key <= toSerial).OrderBy(v => v.Key))
            {
                result.Add(kvp.Value);
            }
        }
        else
        {
            // Normal case: fromSerial <= toSerial
            foreach (var kvp in _versions.OrderBy(v => v.Key))
            {
                if (kvp.Key >= fromSerial && kvp.Key <= toSerial)
                {
                    result.Add(kvp.Value);
                }
            }
        }

        return result;
    }

    /// <summary>
    /// Gets all available serial numbers, ordered ascending.
    /// </summary>
    public List<uint> GetAvailableSerials()
    {
        return _versions.Keys.OrderBy(s => s).ToList();
    }

    /// <summary>
    /// Checks if a version with the specified serial exists.
    /// </summary>
    public bool HasVersion(uint serial)
    {
        return _versions.ContainsKey(serial);
    }

    /// <summary>
    /// Gets the oldest serial number in history.
    /// </summary>
    public uint? GetOldestSerial()
    {
        if (_versions.IsEmpty)
            return null;

        return _versions.Keys.Min();
    }

    /// <summary>
    /// Gets the newest serial number in history.
    /// </summary>
    public uint? GetNewestSerial()
    {
        if (_versions.IsEmpty)
            return null;

        return _versions.Keys.Max();
    }

    /// <summary>
    /// Prunes old versions, keeping only the most recent N versions.
    /// Returns list of serial numbers that were pruned.
    /// </summary>
    public List<uint> PruneOldVersions(int maxVersions)
    {
        var prunedSerials = new List<uint>();

        if (maxVersions <= 0)
        {
            // If maxVersions is 0 or negative, clear all versions
            prunedSerials.AddRange(_versions.Keys);
            _versions.Clear();
            return prunedSerials;
        }

        if (_versions.Count <= maxVersions)
            return prunedSerials; // No pruning needed

        // Get serials ordered by timestamp (newest first), then by serial (descending)
        var versionsToKeep = _versions
            .OrderByDescending(v => v.Value.Timestamp)
            .ThenByDescending(v => v.Key)
            .Take(maxVersions)
            .Select(v => v.Key)
            .ToHashSet();

        // Remove versions not in the keep set
        var keysToRemove = _versions.Keys.Where(k => !versionsToKeep.Contains(k)).ToList();
        foreach (var key in keysToRemove)
        {
            if (_versions.TryRemove(key, out _))
            {
                prunedSerials.Add(key);
            }
        }

        return prunedSerials;
    }

    /// <summary>
    /// Gets all versions as a dictionary snapshot.
    /// </summary>
    public Dictionary<uint, ZoneVersion> GetAllVersions()
    {
        return new Dictionary<uint, ZoneVersion>(_versions);
    }

    /// <summary>
    /// Clears all history.
    /// </summary>
    public void Clear()
    {
        _versions.Clear();
    }

    /// <summary>
    /// Gets the number of versions stored.
    /// </summary>
    public int Count => _versions.Count;

    /// <summary>
    /// Checks if all consecutive versions between fromSerial and toSerial are available.
    /// This is used to validate that IXFR can be served with complete diff chain.
    /// </summary>
    /// <param name="fromSerial">Starting serial (client's current serial)</param>
    /// <param name="toSerial">Target serial (server's current serial)</param>
    /// <returns>True if all required versions are available, false otherwise</returns>
    public bool HasAllVersionsBetween(uint fromSerial, uint toSerial)
    {
        var versions = GetVersionsBetween(fromSerial, toSerial);
        if (versions.Count == 0)
            return false;

        // Must have the fromSerial version
        if (!versions.Any(v => v.Serial == fromSerial))
            return false;

        // For IXFR, we need consecutive versions to calculate diffs
        // Sort by serial and check for gaps
        var sortedSerials = versions.Select(v => v.Serial).OrderBy(s => s).ToList();
        
        // At minimum, we need fromSerial
        return sortedSerials.First() == fromSerial;
    }

    /// <summary>
    /// Gets the list of serial numbers that are missing between fromSerial and toSerial.
    /// Used for diagnostic logging when IXFR cannot be served.
    /// </summary>
    /// <param name="fromSerial">Starting serial</param>
    /// <param name="toSerial">Target serial</param>
    /// <returns>List of available serials in the range (may have gaps)</returns>
    public List<uint> GetAvailableSerialsInRange(uint fromSerial, uint toSerial)
    {
        var versions = GetVersionsBetween(fromSerial, toSerial);
        return versions.Select(v => v.Serial).OrderBy(s => s).ToList();
    }

    /// <summary>
    /// Gets the time elapsed since the most recent version was added.
    /// Used to detect rapid update patterns.
    /// </summary>
    /// <returns>TimeSpan since newest version, or null if no versions exist</returns>
    public TimeSpan? GetTimeSinceNewestVersion()
    {
        if (_versions.IsEmpty)
            return null;

        var newestVersion = _versions.Values.OrderByDescending(v => v.Timestamp).FirstOrDefault();
        if (newestVersion == null)
            return null;

        return DateTime.UtcNow - newestVersion.Timestamp;
    }

    /// <summary>
    /// Gets the number of versions added within the specified time window.
    /// Used to detect rapid update patterns.
    /// </summary>
    /// <param name="window">Time window to check</param>
    /// <returns>Number of versions added within the window</returns>
    public int GetVersionCountInWindow(TimeSpan window)
    {
        var cutoff = DateTime.UtcNow - window;
        return _versions.Values.Count(v => v.Timestamp >= cutoff);
    }

    /// <summary>
    /// Gets version timestamps for debugging and diagnostics.
    /// </summary>
    /// <returns>Dictionary of serial to timestamp</returns>
    public Dictionary<uint, DateTime> GetVersionTimestamps()
    {
        return _versions.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Timestamp);
    }
}
