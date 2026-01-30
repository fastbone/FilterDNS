using FilterDns.Cache;
using FilterDns.Filter;

namespace FilterDns.Xfer;

/// <summary>
/// Represents the differences between two zone versions.
/// </summary>
public class ZoneDiff
{
    public List<FilteredRecord> DeletedRecords { get; set; } = new();
    public List<FilteredRecord> AddedRecords { get; set; } = new();
    public uint FromSerial { get; set; }
    public uint ToSerial { get; set; }
}

/// <summary>
/// Calculates differences between zone versions for IXFR support.
/// </summary>
public static class ZoneDiffCalculator
{
    /// <summary>
    /// Calculates the difference between two zone versions.
    /// Records that exist in oldZone but not in newZone are marked as deleted.
    /// Records that exist in newZone but not in oldZone are marked as added.
    /// Modifications are represented as a delete+add pair.
    /// </summary>
    public static ZoneDiff CalculateDiff(
        List<FilteredRecord> oldZone,
        uint oldSerial,
        List<FilteredRecord> newZone,
        uint newSerial)
    {
        if (oldZone == null)
            throw new ArgumentNullException(nameof(oldZone));
        if (newZone == null)
            throw new ArgumentNullException(nameof(newZone));

        var diff = new ZoneDiff
        {
            FromSerial = oldSerial,
            ToSerial = newSerial
        };

        // Build sets of record keys for efficient comparison
        var oldRecordKeys = new HashSet<string>();
        var oldRecordsByKey = new Dictionary<string, FilteredRecord>();

        foreach (var record in oldZone)
        {
            var key = RecordComparer.GetRecordKey(record);
            oldRecordKeys.Add(key);
            oldRecordsByKey[key] = record;
        }

        var newRecordKeys = new HashSet<string>();
        var newRecordsByKey = new Dictionary<string, FilteredRecord>();

        foreach (var record in newZone)
        {
            var key = RecordComparer.GetRecordKey(record);
            newRecordKeys.Add(key);
            newRecordsByKey[key] = record;
        }

        // Find deleted records: in old but not in new
        foreach (var key in oldRecordKeys)
        {
            if (!newRecordKeys.Contains(key))
            {
                diff.DeletedRecords.Add(oldRecordsByKey[key]);
            }
        }

        // Find added records: in new but not in old
        foreach (var key in newRecordKeys)
        {
            if (!oldRecordKeys.Contains(key))
            {
                diff.AddedRecords.Add(newRecordsByKey[key]);
            }
        }

        return diff;
    }

    /// <summary>
    /// Calculates a sequence of diffs across multiple zone versions.
    /// Returns one diff per version transition, ordered from oldest to newest.
    /// </summary>
    /// <param name="history">Zone history containing versioned records</param>
    /// <param name="fromSerial">Starting serial number (client's current serial)</param>
    /// <param name="toSerial">Ending serial number (server's current serial)</param>
    /// <param name="currentZoneRecords">Current zone records (if toSerial is not yet in history). Can be null.</param>
    public static List<ZoneDiff> CalculateDiffSequence(
        ZoneHistory history,
        uint fromSerial,
        uint toSerial,
        List<FilteredRecord>? currentZoneRecords = null)
    {
        if (history == null)
            throw new ArgumentNullException(nameof(history));

        var diffs = new List<ZoneDiff>();

        // Get all versions between fromSerial and toSerial
        var versions = history.GetVersionsBetween(fromSerial, toSerial);

        // Sort by serial to ensure correct order
        versions = versions.OrderBy(v => v.Serial).ToList();

        // If the fromSerial version doesn't exist, we can't calculate incremental diffs
        // This should be handled by the caller (fallback to AXFR)
        var fromVersion = versions.FirstOrDefault(v => v.Serial == fromSerial);
        if (fromVersion == null)
        {
            return diffs; // Empty - caller should fallback to AXFR
        }

        // Check if toSerial exists in history
        var toVersion = versions.FirstOrDefault(v => v.Serial == toSerial);
        var needsCurrentZoneDiff = toVersion == null && currentZoneRecords != null;

        // Calculate diff for each transition between consecutive versions
        for (int i = 0; i < versions.Count - 1; i++)
        {
            var currentVersion = versions[i];
            var nextVersion = versions[i + 1];

            var diff = CalculateDiff(
                currentVersion.Records,
                currentVersion.Serial,
                nextVersion.Records,
                nextVersion.Serial);

            diffs.Add(diff);
        }

        // CRITICAL FIX: If toSerial is not in history yet (current zone not saved to history),
        // we need to calculate the diff from the last version in history to the current zone
        if (needsCurrentZoneDiff)
        {
            if (versions.Count == 0)
            {
                // No versions in history - calculate diff from fromVersion to current zone
                var diff = CalculateDiff(
                    fromVersion.Records,
                    fromSerial,
                    currentZoneRecords!,
                    toSerial);
                diffs.Add(diff);
            }
            else
            {
                // Calculate diff from last version in history to current zone
                var lastVersion = versions.Last();
                var diff = CalculateDiff(
                    lastVersion.Records,
                    lastVersion.Serial,
                    currentZoneRecords!,
                    toSerial);
                diffs.Add(diff);
            }
        }
        else if (toVersion != null && versions.Count > 0)
        {
            // toSerial exists in history, but might not be the last version
            // If there are versions after toSerial, we need to include them up to toSerial
            var toVersionIndex = versions.IndexOf(toVersion);
            if (toVersionIndex < versions.Count - 1)
            {
                // There are versions after toSerial - this shouldn't happen if GetVersionsBetween works correctly
                // But handle it anyway: calculate diffs up to toSerial
                for (int i = toVersionIndex; i < versions.Count - 1; i++)
                {
                    var currentVersion = versions[i];
                    var nextVersion = versions[i + 1];
                    if (nextVersion.Serial <= toSerial)
                    {
                        var diff = CalculateDiff(
                            currentVersion.Records,
                            currentVersion.Serial,
                            nextVersion.Records,
                            nextVersion.Serial);
                        diffs.Add(diff);
                    }
                }
            }
        }

        return diffs;
    }

    /// <summary>
    /// Calculates a cumulative diff from fromSerial to toSerial.
    /// This combines all intermediate changes into a single diff.
    /// </summary>
    public static ZoneDiff CalculateCumulativeDiff(
        ZoneHistory history,
        uint fromSerial,
        uint toSerial)
    {
        if (history == null)
            throw new ArgumentNullException(nameof(history));

        var fromVersion = history.GetVersion(fromSerial);
        var toVersion = history.GetVersion(toSerial);

        if (fromVersion == null || toVersion == null)
        {
            throw new ArgumentException($"Cannot calculate diff: missing version(s). From: {fromSerial}, To: {toSerial}");
        }

        return CalculateDiff(
            fromVersion.Records,
            fromSerial,
            toVersion.Records,
            toSerial);
    }
}
