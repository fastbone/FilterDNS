using System.Text;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Cache;
using FilterDns.Filter;

namespace FilterDns.Export;

/// <summary>
/// Exports filtered DNS zones to BIND DNS format for debugging purposes.
/// </summary>
public static class ZoneExporter
{
    /// <summary>
    /// Exports a cached zone to BIND DNS format string.
    /// </summary>
    /// <param name="cachedZone">The cached zone to export</param>
    /// <param name="zoneName">The zone name</param>
    /// <returns>BIND DNS format zone file content</returns>
    public static string ExportToBindFormat(CachedZone cachedZone, string zoneName)
    {
        return ExportToBindFormat(cachedZone.Records, zoneName);
    }

    /// <summary>
    /// Exports filtered records to BIND DNS format string.
    /// </summary>
    /// <param name="records">The filtered records to export</param>
    /// <param name="zoneName">The zone name</param>
    /// <returns>BIND DNS format zone file content</returns>
    public static string ExportToBindFormat(List<FilteredRecord> records, string zoneName)
    {
        var sb = new StringBuilder();
        var normalizedZoneName = zoneName.TrimEnd('.');
        
        // Write zone header
        sb.AppendLine($"$ORIGIN {normalizedZoneName}.");
        
        // Find SOA record to determine default TTL
        var soaRecord = records.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
        var defaultTtl = soaRecord?.TimeToLive ?? 3600;
        sb.AppendLine($"$TTL {defaultTtl}");
        sb.AppendLine();

        // Sort records: SOA first, then NS, then others
        var sortedRecords = records
            .OrderBy(r => r.RecordType == ResourceRecordType.SOA ? 0 : 1)
            .ThenBy(r => r.RecordType == ResourceRecordType.NS ? 0 : 1)
            .ThenBy(r => r.DomainName)
            .ToList();

        foreach (var record in sortedRecords)
        {
            var line = FormatRecord(record, normalizedZoneName);
            if (!string.IsNullOrEmpty(line))
            {
                sb.AppendLine(line);
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Exports a zone to a file in BIND DNS format.
    /// </summary>
    /// <param name="records">The filtered records to export</param>
    /// <param name="zoneName">The zone name</param>
    /// <param name="filePath">The output file path</param>
    public static async Task ExportToFileAsync(
        List<FilteredRecord> records,
        string zoneName,
        string filePath)
    {
        var content = ExportToBindFormat(records, zoneName);
        await File.WriteAllTextAsync(filePath, content);
    }

    private static string FormatRecord(FilteredRecord record, string zoneName)
    {
        var domainName = FormatDomainName(record.DomainName, zoneName);
        var ttl = record.TimeToLive;
        var recordClass = FormatRecordClass(record.RecordClass);
        var recordType = record.RecordType.ToString().ToUpper();
        var rdata = FormatRdata(record, zoneName);

        if (string.IsNullOrEmpty(rdata))
        {
            return string.Empty;
        }

        return $"{domainName,-30} {ttl,-8} {recordClass,-4} {recordType,-6} {rdata}";
    }

    private static string FormatDomainName(string domainName, string zoneName)
    {
        var normalized = domainName.TrimEnd('.');
        var normalizedZone = zoneName.TrimEnd('.');

        if (normalized.Equals(normalizedZone, StringComparison.OrdinalIgnoreCase))
        {
            return "@";
        }

        // If it's a subdomain, return relative name
        if (normalized.EndsWith("." + normalizedZone, StringComparison.OrdinalIgnoreCase))
        {
            var relativeName = normalized.Substring(0, normalized.Length - normalizedZone.Length - 1);
            return relativeName;
        }

        // Return full name with trailing dot
        return normalized + ".";
    }

    private static string FormatRecordClass(QueryClass queryClass)
    {
        return queryClass switch
        {
            QueryClass.IN => "IN",
            QueryClass.CS => "CS",
            QueryClass.CH => "CH",
            QueryClass.HS => "HS",
            _ => queryClass.ToString().ToUpper()
        };
    }

    private static string FormatRdata(FilteredRecord record, string zoneName)
    {
        // Handle SOA record
        if (record.SoaData != null)
        {
            return FormatSoa(record.SoaData);
        }

        // Handle NS record
        if (record.NsName != null)
        {
            return FormatNs(record.NsName);
        }

        // Handle other record types from OriginalRecord
        if (record.OriginalRecord != null)
        {
            return FormatOriginalRecord(record.OriginalRecord, zoneName);
        }

        return string.Empty;
    }

    private static string FormatSoa(SoaRecordData soa)
    {
        return $"{soa.MName.TrimEnd('.')} {soa.RName.TrimEnd('.')} ({soa.Serial} {soa.Refresh} {soa.Retry} {soa.Expire} {soa.Minimum})";
    }

    private static string FormatNs(string nsName)
    {
        return nsName.TrimEnd('.') + ".";
    }

    private static string FormatOriginalRecord(DnsResourceRecord record, string zoneName)
    {
        return record switch
        {
            ARecord a => FormatA(a),
            AaaaRecord aaaa => FormatAaaa(aaaa),
            MxRecord mx => FormatMx(mx),
            CNameRecord cname => FormatCname(cname),
            TxtRecord txt => FormatTxt(txt),
            SrvRecord srv => FormatSrv(srv),
            PtrRecord ptr => FormatPtr(ptr),
            NsRecord ns => FormatNs(ns.NSDName.Value),
            SoaRecord soa => FormatSoaFromRecord(soa),
            CaaRecord caa => FormatCaa(caa),
            _ => FormatUnknown(record)
        };
    }

    private static string FormatA(ARecord a)
    {
        return a.Address.ToString();
    }

    private static string FormatAaaa(AaaaRecord aaaa)
    {
        return aaaa.Address.ToString();
    }

    private static string FormatMx(MxRecord mx)
    {
        return $"{mx.Preference} {mx.Exchange.Value.TrimEnd('.')}.";
    }

    private static string FormatCname(CNameRecord cname)
    {
        return cname.CanonicalName.Value.TrimEnd('.') + ".";
    }

    private static string FormatTxt(TxtRecord txt)
    {
        // TXT records can have multiple strings, join them
        var text = string.Join("", txt.Text);
        // Escape quotes and wrap in quotes if needed
        if (text.Contains(' ') || text.Contains('"'))
        {
            text = "\"" + text.Replace("\"", "\\\"") + "\"";
        }
        return text;
    }

    private static string FormatSrv(SrvRecord srv)
    {
        return $"{srv.Priority} {srv.Weight} {srv.Port} {srv.Target.Value.TrimEnd('.')}.";
    }

    private static string FormatPtr(PtrRecord ptr)
    {
        return ptr.PtrDomainName.Value.TrimEnd('.') + ".";
    }

    private static string FormatSoaFromRecord(SoaRecord soa)
    {
        return $"{soa.MName.Value.TrimEnd('.')} {soa.RName.Value.TrimEnd('.')} ({soa.Serial} {soa.Refresh} {soa.Retry} {soa.Expire} {soa.Minimum})";
    }

    private static string FormatCaa(CaaRecord caa)
    {
        // CAA format: flags tag "value"
        // Example: 0 issue "letsencrypt.org"
        var value = caa.Value;
        // Escape quotes in value if needed
        if (value.Contains('"'))
        {
            value = value.Replace("\"", "\\\"");
        }
        return $"{caa.Flags} {caa.Tag} \"{value}\"";
    }

    private static string FormatUnknown(DnsResourceRecord record)
    {
        // For unknown record types, output a comment with the type
        // In a real implementation, you might want to serialize the raw RDATA
        return $"; Unknown record type: {record.RecordType} (not implemented)";
    }
}

