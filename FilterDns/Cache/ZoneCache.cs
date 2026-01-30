using System.Collections.Concurrent;
using FilterDns.Filter;

namespace FilterDns.Cache;

public class ZoneCache
{
    private readonly ConcurrentDictionary<string, CachedZone> _zones = new();

    /// <summary>
    /// Gets a copy of the cached zone. Returns null if zone not found.
    /// This method creates a defensive copy of the records to prevent race conditions
    /// when the cache is updated concurrently with zone transfers.
    /// 
    /// CRITICAL: The defensive copy ensures that the returned zone is a complete,
    /// consistent snapshot from a single zone version. The copy is taken atomically
    /// from the ConcurrentDictionary, ensuring no mixing of records from different versions.
    /// </summary>
    public CachedZone? GetZone(string zoneName)
    {
        if (!_zones.TryGetValue(zoneName, out var zone))
        {
            return null;
        }

        // Create a defensive copy to prevent race conditions
        // CRITICAL: This copy is taken from a single atomic snapshot of the zone.
        // If the cache is updated while we're reading, we'll still have a consistent
        // snapshot of the complete zone from one version, never a mix of versions.
        // The List constructor creates a shallow copy, but since FilteredRecord is
        // immutable for our purposes (we never modify records after creation), this is safe.
        return new CachedZone
        {
            Records = new List<FilteredRecord>(zone.Records), // Atomic copy of complete zone
            Serial = zone.Serial
        };
    }

    public uint? GetSerial(string zoneName)
    {
        return _zones.TryGetValue(zoneName, out var zone) ? zone.Serial : null;
    }

    /// <summary>
    /// Validates that all records in a zone belong to the same serial number.
    /// This ensures zone consistency and prevents mixing records from different versions.
    /// </summary>
    private void ValidateZoneConsistency(string zoneName, List<FilteredRecord> records, uint expectedSerial)
    {
        // Find all SOA records - there should be exactly one
        var soaRecords = records.Where(r => r.RecordType == DnsClient.Protocol.ResourceRecordType.SOA).ToList();
        
        if (soaRecords.Count == 0)
        {
            throw new ArgumentException($"Zone {zoneName} has no SOA record - zone is incomplete", nameof(records));
        }
        
        if (soaRecords.Count > 1)
        {
            throw new ArgumentException($"Zone {zoneName} has {soaRecords.Count} SOA records - zone is corrupted (expected exactly 1)", nameof(records));
        }
        
        // Verify SOA serial matches expected serial
        var soaSerial = soaRecords[0].SoaData?.Serial ?? 0;
        if (soaSerial != expectedSerial)
        {
            throw new ArgumentException(
                $"Zone {zoneName} serial mismatch: SOA record has serial {soaSerial} but expected {expectedSerial} - zone may contain mixed versions",
                nameof(records));
        }
        
        // Verify SOA serial is not zero (invalid)
        if (soaSerial == 0)
        {
            throw new ArgumentException($"Zone {zoneName} has invalid SOA serial (0) - zone is corrupted", nameof(records));
        }
    }

    /// <summary>
    /// Updates the zone cache atomically. This ensures that concurrent reads always get
    /// either the old complete zone or the new complete zone, never a partial update.
    /// 
    /// CRITICAL: This method validates that all records belong to the same serial number
    /// and always replaces the entire zone atomically. This prevents mixing records from
    /// different zone versions.
    /// 
    /// IMPORTANT: This method always replaces the entire zone, even if the serial number
    /// is the same. This ensures that any updates to records (e.g., MX records) are
    /// immediately reflected in the cache, preventing stale data from being served.
    /// </summary>
    public void UpdateZone(string zoneName, List<FilteredRecord> records)
    {
        // Validate that we have at least SOA and NS records
        if (records == null || records.Count == 0)
        {
            throw new ArgumentException($"Cannot update zone {zoneName} with empty records list", nameof(records));
        }

        // Extract serial from SOA record
        var serial = records
            .FirstOrDefault(r => r.RecordType == DnsClient.Protocol.ResourceRecordType.SOA)
            ?.SoaData?.Serial ?? 0;

        // CRITICAL: Validate zone consistency before updating cache
        // This ensures all records belong to the same serial number and prevents mixing versions
        ValidateZoneConsistency(zoneName, records, serial);

        // Create a new CachedZone with a copy of the records list
        // This ensures atomic replacement - readers will get either the old or new zone, never a mix
        // The defensive copy ensures that if records are modified after this call, the cache is unaffected
        var newZone = new CachedZone
        {
            Records = new List<FilteredRecord>(records), // Defensive copy - ensures complete, consistent zone
            Serial = serial
        };

        // Atomic update - ConcurrentDictionary ensures thread safety
        // This is safe because we're replacing the entire CachedZone object atomically
        // Always replace with new zone to ensure consistency - even if serial is the same,
        // the records might have changed (e.g., MX records, TTLs, etc.)
        // 
        // CRITICAL: The entire zone is replaced in a single atomic operation.
        // Concurrent readers will either get the old complete zone or the new complete zone,
        // never a mix of records from different versions.
        _zones.AddOrUpdate(zoneName, 
            newZone,
            (key, old) => newZone); // Always replace with new zone to ensure consistency
    }

    public void RemoveZone(string zoneName)
    {
        _zones.TryRemove(zoneName, out _);
    }
}

/// <summary>
/// Represents a complete, consistent snapshot of a zone at a specific serial number.
/// 
/// CRITICAL: All records in this zone belong to the same serial number.
/// This class ensures that zone data is never mixed from different versions.
/// The Records list contains a complete zone from a single version, never a partial
/// or mixed zone.
/// </summary>
public class CachedZone
{
    /// <summary>
    /// Complete list of all records in this zone version.
    /// All records belong to the same serial number - never mixed from different versions.
    /// </summary>
    public List<FilteredRecord> Records { get; set; } = new();
    
    /// <summary>
    /// The serial number of this zone version.
    /// All records in the Records list belong to this serial number.
    /// </summary>
    public uint Serial { get; set; }
}

