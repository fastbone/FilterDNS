using System.Net;
using System.Net.Sockets;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Config;

namespace FilterDns.Filter;

// Wrapper to hold filtered record data
public class FilteredRecord
{
    public string DomainName { get; set; } = string.Empty;
    public ResourceRecordType RecordType { get; set; }
    public QueryClass RecordClass { get; set; }
    public int TimeToLive { get; set; }
    public DnsResourceRecord OriginalRecord { get; set; } = null!;
    public SoaRecordData? SoaData { get; set; }
    public string? NsName { get; set; }
}

public class SoaRecordData
{
    public string MName { get; set; } = string.Empty;
    public string RName { get; set; } = string.Empty;
    public uint Serial { get; set; }
    public uint Refresh { get; set; }
    public uint Retry { get; set; }
    public uint Expire { get; set; }
    public uint Minimum { get; set; }
}

public class RecordFilter
{
    public static List<FilteredRecord> ApplyFilters(
        IEnumerable<DnsResourceRecord> zoneRecords,
        ZoneConfig config,
        string zoneName)
    {
        var filteredRecords = new List<FilteredRecord>();
        SoaRecord? soaRecord = null;
        var normalizedZoneName = zoneName.TrimEnd('.').ToLowerInvariant();

        // Process all records individually
        // Each record is evaluated independently - multiple A/AAAA records for the same hostname
        // are each checked separately, filtering out only those with private IPs
        foreach (var record in zoneRecords)
        {
            if (record.RecordType == ResourceRecordType.SOA && record is SoaRecord soa)
            {
                soaRecord = soa;
            }
            else if (record.RecordType == ResourceRecordType.NS)
            {
                // Skip NS records at zone apex (will be replaced)
                var recordName = record.DomainName.Value.TrimEnd('.').ToLowerInvariant();
                if (!recordName.Equals(normalizedZoneName))
                {
                    // Keep NS records for subdomains
                    filteredRecords.Add(new FilteredRecord
                    {
                        DomainName = record.DomainName.Value,
                        RecordType = record.RecordType,
                        RecordClass = record.RecordClass,
                        TimeToLive = record.TimeToLive,
                        OriginalRecord = record
                    });
                }
            }
            else if (record.RecordType == ResourceRecordType.A && record is ARecord aRecord)
            {
                // For A records: if FilterPrivateIPs is enabled, only keep records with public IPs
                // Each A record is evaluated independently, even if multiple exist for the same hostname
                if (!config.FilterPrivateIPs || !IsPrivateIP(aRecord.Address, config))
                {
                    filteredRecords.Add(new FilteredRecord
                    {
                        DomainName = record.DomainName.Value,
                        RecordType = record.RecordType,
                        RecordClass = record.RecordClass,
                        TimeToLive = record.TimeToLive,
                        OriginalRecord = record
                    });
                }
            }
            else if (record.RecordType == ResourceRecordType.AAAA && record is AaaaRecord aaaaRecord)
            {
                // For AAAA records: if FilterPrivateIPs is enabled, only keep records with public IPs
                // Each AAAA record is evaluated independently, even if multiple exist for the same hostname
                if (!config.FilterPrivateIPs || !IsPrivateIP(aaaaRecord.Address, config))
                {
                    filteredRecords.Add(new FilteredRecord
                    {
                        DomainName = record.DomainName.Value,
                        RecordType = record.RecordType,
                        RecordClass = record.RecordClass,
                        TimeToLive = record.TimeToLive,
                        OriginalRecord = record
                    });
                }
            }
            else
            {
                // Keep all other records unchanged (including MX, TXT, CNAME, SRV, etc.)
                // Note: Only NS records at zone apex are filtered/replaced above
                var recordName = record.DomainName.Value.TrimEnd('.').ToLowerInvariant();
                var isZoneApex = recordName.Equals(normalizedZoneName);
                
                // Debug: Log MX records at zone apex to help diagnose filtering issues
                if (record.RecordType == ResourceRecordType.MX && record is MxRecord mx && isZoneApex)
                {
                    // MX records at zone apex are preserved (not filtered like NS records)
                    // This helps diagnose issues where MX records might appear to be filtered
                }
                
                filteredRecords.Add(new FilteredRecord
                {
                    DomainName = record.DomainName.Value,
                    RecordType = record.RecordType,
                    RecordClass = record.RecordClass,
                    TimeToLive = record.TimeToLive,
                    OriginalRecord = record
                });
            }
        }

        // Filter SOA record
        if (soaRecord != null)
        {
            var filteredSoa = FilterSoa(soaRecord, config);
            filteredRecords.Insert(0, filteredSoa); // SOA should be first
        }

        // Add configured NS records at zone apex
        var nsNames = new List<string> { config.Ns1, config.Ns2 };
        if (!string.IsNullOrEmpty(config.Ns3)) nsNames.Add(config.Ns3);
        if (!string.IsNullOrEmpty(config.Ns4)) nsNames.Add(config.Ns4);

        // Get TTL from existing NS records or use default
        var nsTtl = zoneRecords
            .FirstOrDefault(r => r.RecordType == ResourceRecordType.NS && 
                                 r.DomainName.Value.TrimEnd('.').ToLowerInvariant().Equals(normalizedZoneName))
            ?.TimeToLive ?? 3600;

        var zoneNameDns = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";
        foreach (var nsName in nsNames)
        {
            filteredRecords.Add(new FilteredRecord
            {
                DomainName = zoneNameDns,
                RecordType = ResourceRecordType.NS,
                RecordClass = QueryClass.IN,
                TimeToLive = nsTtl,
                NsName = nsName.EndsWith('.') ? nsName : $"{nsName}."
            });
        }

        return filteredRecords;
    }

    private static FilteredRecord FilterSoa(SoaRecord soa, ZoneConfig config)
    {
        // Replace mname with NS1
        var newMname = config.Ns1.EndsWith('.') ? config.Ns1 : $"{config.Ns1}.";

        // Replace rname only if configured, otherwise preserve original
        var newRname = !string.IsNullOrEmpty(config.SoaRname)
            ? (config.SoaRname.EndsWith('.') ? config.SoaRname : $"{config.SoaRname}.")
            : soa.RName.Value;

        return new FilteredRecord
        {
            DomainName = soa.DomainName.Value,
            RecordType = ResourceRecordType.SOA,
            RecordClass = soa.RecordClass,
            TimeToLive = soa.TimeToLive,
            SoaData = new SoaRecordData
            {
                MName = newMname,
                RName = newRname,
                Serial = (uint)soa.Serial,
                Refresh = (uint)soa.Refresh,
                Retry = (uint)soa.Retry,
                Expire = (uint)soa.Expire,
                Minimum = (uint)soa.Minimum
            }
        };
    }

    /// <summary>
    /// Checks if an IP address is a private address based on configured ranges or default RFC 1918 ranges.
    /// </summary>
    /// <param name="address">The IP address to check</param>
    /// <param name="config">The zone configuration containing optional custom private IP ranges</param>
    /// <returns>True if the IP is private, false otherwise</returns>
    private static bool IsPrivateIP(IPAddress address, ZoneConfig config)
    {
        // If custom ranges are configured, use those
        if (config.PrivateIPRanges != null && config.PrivateIPRanges.Count > 0)
        {
            return IsInRanges(address, config.PrivateIPRanges);
        }
        
        // Otherwise, use default RFC 1918 ranges
        return IsPrivateIPDefault(address);
    }

    /// <summary>
    /// Checks if an IP address matches any of the configured CIDR ranges.
    /// </summary>
    private static bool IsInRanges(IPAddress address, List<string> ranges)
    {
        foreach (var range in ranges)
        {
            if (IsInRange(address, range))
                return true;
        }
        return false;
    }

    /// <summary>
    /// Checks if an IP address is within a CIDR range or matches a single IP.
    /// </summary>
    private static bool IsInRange(IPAddress address, string range)
    {
        if (IPAddress.TryParse(range, out var singleIp))
        {
            // Single IP address - exact match
            return address.Equals(singleIp);
        }
        
        if (range.Contains('/'))
        {
            // CIDR notation
            var parts = range.Split('/');
            if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var networkIp) && int.TryParse(parts[1], out var prefixLength))
            {
                return IsInCidrRange(address, networkIp, prefixLength);
            }
        }
        
        return false;
    }

    /// <summary>
    /// Checks if an IP address is within a CIDR range.
    /// </summary>
    private static bool IsInCidrRange(IPAddress address, IPAddress networkAddress, int prefixLength)
    {
        var addressBytes = address.GetAddressBytes();
        var networkBytes = networkAddress.GetAddressBytes();
        
        if (addressBytes.Length != networkBytes.Length)
            return false;
        
        var byteLength = (prefixLength + 7) / 8; // Number of bytes to compare
        
        for (int i = 0; i < byteLength; i++)
        {
            if (addressBytes[i] != networkBytes[i])
                return false;
        }
        
        // Check remaining bits if prefix length is not byte-aligned
        if (prefixLength % 8 != 0)
        {
            var bitsInLastByte = prefixLength % 8;
            var mask = (byte)(0xFF << (8 - bitsInLastByte));
            if ((addressBytes[byteLength] & mask) != (networkBytes[byteLength] & mask))
                return false;
        }
        
        return true;
    }

    /// <summary>
    /// Checks if an IP address is a private (RFC 1918) or link-local address using default ranges.
    /// </summary>
    private static bool IsPrivateIPDefault(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            // IPv4 private ranges (RFC 1918):
            // 10.0.0.0/8
            // 172.16.0.0/12
            // 192.168.0.0/16
            // Also include loopback (127.0.0.0/8) and link-local (169.254.0.0/16)
            var bytes = address.GetAddressBytes();
            
            // 10.0.0.0/8
            if (bytes[0] == 10)
                return true;
            
            // 172.16.0.0/12 (172.16.0.0 to 172.31.255.255)
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                return true;
            
            // 192.168.0.0/16
            if (bytes[0] == 192 && bytes[1] == 168)
                return true;
            
            // 127.0.0.0/8 (loopback)
            if (bytes[0] == 127)
                return true;
            
            // 169.254.0.0/16 (link-local)
            if (bytes[0] == 169 && bytes[1] == 254)
                return true;
        }
        else if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            // IPv6 private ranges:
            // fc00::/7 (unique local addresses)
            // fe80::/10 (link-local addresses)
            // ::1 (loopback)
            var bytes = address.GetAddressBytes();
            
            // fc00::/7 (unique local addresses)
            if ((bytes[0] & 0xFE) == 0xFC)
                return true;
            
            // fe80::/10 (link-local addresses)
            if ((bytes[0] & 0xFF) == 0xFE && (bytes[1] & 0xC0) == 0x80)
                return true;
            
            // ::1 (loopback)
            if (address.Equals(IPAddress.IPv6Loopback))
                return true;
        }
        
        return false;
    }
}
