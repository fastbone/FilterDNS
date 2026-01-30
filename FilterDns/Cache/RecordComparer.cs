using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using DnsClient.Protocol;
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

        return $"{domainName}|{(int)record.RecordType}|{(int)record.RecordClass}|{rdataHash}";
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

        // A records: compare IP address
        if (a.RecordType == ResourceRecordType.A)
        {
            var aIp = ExtractIpAddress(a, AddressFamily.InterNetwork);
            var bIp = ExtractIpAddress(b, AddressFamily.InterNetwork);
            return aIp != null && bIp != null && aIp.Equals(bIp);
        }

        // AAAA records: compare IPv6 address
        if (a.RecordType == ResourceRecordType.AAAA)
        {
            var aIp = ExtractIpAddress(a, AddressFamily.InterNetworkV6);
            var bIp = ExtractIpAddress(b, AddressFamily.InterNetworkV6);
            return aIp != null && bIp != null && aIp.Equals(bIp);
        }

        // For other record types, compare raw RDATA
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

        if (record.RecordType == ResourceRecordType.A || record.RecordType == ResourceRecordType.AAAA)
        {
            var ip = ExtractIpAddress(record, 
                record.RecordType == ResourceRecordType.A ? AddressFamily.InterNetwork : AddressFamily.InterNetworkV6);
            return ComputeHash(ip?.ToString() ?? string.Empty);
        }

        // For other types, use raw RDATA
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
        if (record.OriginalRecord != null)
        {
            // Try to get raw RDATA from original record using reflection
            var rawRdata = TryGetRawRdataFromOriginal(record.OriginalRecord);
            if (rawRdata != null && rawRdata.Length > 0)
            {
                return rawRdata;
            }
        }

        // Fallback: serialize based on known types
        return record.RecordType switch
        {
            ResourceRecordType.SOA when record.SoaData != null => SerializeSoaRdata(record.SoaData),
            ResourceRecordType.NS when record.NsName != null => SerializeNsRdata(record.NsName),
            _ => Array.Empty<byte>()
        };
    }

    /// <summary>
    /// Tries to extract raw RDATA from DnsResourceRecord using reflection.
    /// </summary>
    private static byte[]? TryGetRawRdataFromOriginal(DnsResourceRecord record)
    {
        try
        {
            // Try to access Raw property
            var rawProperty = record.GetType().GetProperty("Raw", 
                System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance);
            if (rawProperty?.PropertyType == typeof(byte[]))
            {
                var rawValue = rawProperty.GetValue(record) as byte[];
                if (rawValue != null && rawValue.Length > 0)
                {
                    // Extract RDATA portion (skip name, type, class, TTL - typically 12-16 bytes)
                    // This is a simplified approach - full parsing would be more accurate
                    if (rawValue.Length > 16)
                    {
                        // Find RDATA length (2 bytes after TTL)
                        var rdataLength = (rawValue[rawValue.Length - 2] << 8) | rawValue[rawValue.Length - 1];
                        // For now, return the last portion which should contain RDATA
                        // In practice, we'd need proper DNS record parsing
                        return rawValue;
                    }
                    return rawValue;
                }
            }
        }
        catch
        {
            // Reflection failed, fall back to type-specific serialization
        }

        return null;
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
    /// Extracts IP address from record.
    /// </summary>
    private static IPAddress? ExtractIpAddress(FilteredRecord record, AddressFamily family)
    {
        if (record.OriginalRecord is ARecord aRecord && family == AddressFamily.InterNetwork)
        {
            return aRecord.Address;
        }

        if (record.OriginalRecord is AaaaRecord aaaaRecord && family == AddressFamily.InterNetworkV6)
        {
            return aaaaRecord.Address;
        }

        return null;
    }

    /// <summary>
    /// Serializes SOA RDATA.
    /// </summary>
    private static byte[] SerializeSoaRdata(SoaRecordData soa)
    {
        var data = new List<byte>();
        WriteDomainName(data, soa.MName);
        WriteDomainName(data, soa.RName);
        WriteUInt32(data, soa.Serial);
        WriteUInt32(data, soa.Refresh);
        WriteUInt32(data, soa.Retry);
        WriteUInt32(data, soa.Expire);
        WriteUInt32(data, soa.Minimum);
        return data.ToArray();
    }

    /// <summary>
    /// Serializes NS RDATA.
    /// </summary>
    private static byte[] SerializeNsRdata(string nsName)
    {
        var data = new List<byte>();
        WriteDomainName(data, nsName);
        return data.ToArray();
    }

    /// <summary>
    /// Writes a domain name in DNS format.
    /// </summary>
    private static void WriteDomainName(List<byte> data, string name)
    {
        var parts = name.TrimEnd('.').Split('.');
        foreach (var part in parts)
        {
            if (string.IsNullOrEmpty(part)) continue;
            var partBytes = Encoding.UTF8.GetBytes(part);
            data.Add((byte)partBytes.Length);
            data.AddRange(partBytes);
        }
        data.Add(0); // Terminator
    }

    /// <summary>
    /// Writes a 32-bit unsigned integer in network byte order.
    /// </summary>
    private static void WriteUInt32(List<byte> data, uint value)
    {
        data.Add((byte)(value >> 24));
        data.Add((byte)(value >> 16));
        data.Add((byte)(value >> 8));
        data.Add((byte)(value & 0xFF));
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
