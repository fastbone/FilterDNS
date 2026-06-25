using System.Security.Cryptography;
using System.Text;
using DnsClient.Protocol;
using FilterDns.Dns;
using FilterDns.Filter;

namespace FilterDns.Cache;

/// <summary>
/// Utility class for comparing FilteredRecord objects for equality.
/// Used for calculating zone diffs in IXFR support.
/// </summary>
public static class RecordComparer
{
    /// <summary>
    /// Compares two FilteredRecord objects for equality.
    /// Records are considered equal if they have the same domain name, type, class, and RDATA.
    /// </summary>
    public static bool RecordsEqual(FilteredRecord a, FilteredRecord b)
    {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;

        // Compare basic fields
        if (!string.Equals(a.DomainName, b.DomainName, StringComparison.OrdinalIgnoreCase))
            return false;

        if (a.RecordType != b.RecordType)
            return false;

        if (a.RecordClass != b.RecordClass)
            return false;

        if (a.TimeToLive != b.TimeToLive)
            return false;

        // Compare RDATA based on record type
        return CompareRdata(a, b);
    }

    /// <summary>
    /// Creates a unique key for a record that can be used for hashing and comparison.
    /// Format: "{DomainName}|{RecordType}|{RecordClass}|{RdataHash}"
    /// </summary>
    public static string GetRecordKey(FilteredRecord record)
    {
        if (record == null)
            throw new ArgumentNullException(nameof(record));

        var domainName = record.DomainName.TrimEnd('.').ToLowerInvariant();
        var rdataHash = GetRdataHash(record);

        return $"{domainName}|{(int)record.RecordType}|{(int)record.RecordClass}|{record.TimeToLive}|{rdataHash}";
    }

    /// <summary>
    /// Compares the RDATA portion of two records based on their type.
    /// </summary>
    private static bool CompareRdata(FilteredRecord a, FilteredRecord b)
    {
        // SOA records: compare all SOA fields
        if (a.RecordType == ResourceRecordType.SOA)
        {
            if (a.SoaData == null && b.SoaData == null) return true;
            if (a.SoaData == null || b.SoaData == null) return false;

            return a.SoaData.MName.Equals(b.SoaData.MName, StringComparison.OrdinalIgnoreCase) &&
                   a.SoaData.RName.Equals(b.SoaData.RName, StringComparison.OrdinalIgnoreCase) &&
                   a.SoaData.Serial == b.SoaData.Serial &&
                   a.SoaData.Refresh == b.SoaData.Refresh &&
                   a.SoaData.Retry == b.SoaData.Retry &&
                   a.SoaData.Expire == b.SoaData.Expire &&
                   a.SoaData.Minimum == b.SoaData.Minimum;
        }

        // NS records: compare NS name
        if (a.RecordType == ResourceRecordType.NS)
        {
            var aNsName = a.NsName ?? ExtractNsNameFromOriginal(a);
            var bNsName = b.NsName ?? ExtractNsNameFromOriginal(b);
            return string.Equals(aNsName, bNsName, StringComparison.OrdinalIgnoreCase);
        }

        return CompareRawRdata(a, b);
    }

    /// <summary>
    /// Gets a hash of the RDATA for use in record keys.
    /// </summary>
    private static string GetRdataHash(FilteredRecord record)
    {
        if (record.RecordType == ResourceRecordType.SOA && record.SoaData != null)
        {
            var soaString = $"{record.SoaData.MName}|{record.SoaData.RName}|{record.SoaData.Serial}|{record.SoaData.Refresh}|{record.SoaData.Retry}|{record.SoaData.Expire}|{record.SoaData.Minimum}";
            return ComputeHash(soaString);
        }

        if (record.RecordType == ResourceRecordType.NS)
        {
            var nsName = record.NsName ?? ExtractNsNameFromOriginal(record);
            return ComputeHash(nsName ?? string.Empty);
        }

        var rawRdata = GetRawRdata(record);
        return ComputeHash(Convert.ToBase64String(rawRdata));
    }

    /// <summary>
    /// Compares raw RDATA bytes for records that don't have type-specific comparison.
    /// </summary>
    private static bool CompareRawRdata(FilteredRecord a, FilteredRecord b)
    {
        var aRdata = GetRawRdata(a);
        var bRdata = GetRawRdata(b);

        if (aRdata.Length != bRdata.Length)
            return false;

        for (int i = 0; i < aRdata.Length; i++)
        {
            if (aRdata[i] != bRdata[i])
                return false;
        }

        return true;
    }

    /// <summary>
    /// Extracts raw RDATA bytes from a FilteredRecord.
    /// </summary>
    private static byte[] GetRawRdata(FilteredRecord record)
    {
        return RDataSerializer.Serialize(record);
    }

    /// <summary>
    /// Extracts NS name from original record if available.
    /// </summary>
    private static string? ExtractNsNameFromOriginal(FilteredRecord record)
    {
        if (record.OriginalRecord is NsRecord nsRecord)
        {
            return nsRecord.NSDName.Value;
        }
        return null;
    }

    /// <summary>
    /// Computes a SHA256 hash of the input string and returns it as a hex string.
    /// </summary>
    private static string ComputeHash(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
