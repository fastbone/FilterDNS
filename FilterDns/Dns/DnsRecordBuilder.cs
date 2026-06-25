using System.Net;
using System.Reflection;
using System.Text;
using DnsClient.Protocol;
using FilterDns.Filter;

namespace FilterDns.Dns;

public static class DnsRecordBuilder
{
    public static byte[] BuildZoneTransferResponse(
        List<FilteredRecord> records,
        ushort queryId,
        string zoneName)
    {
        var data = new List<byte>();
        var nameCompression = new Dictionary<string, int>(); // Track name positions for compression

        // Header
        DnsMessageParser.WriteUInt16(data, queryId);
        DnsMessageParser.WriteUInt16(data, 0x8500); // Response, Authoritative, NoError
        DnsMessageParser.WriteUInt16(data, 1); // QDCOUNT
        DnsMessageParser.WriteUInt16(data, (ushort)records.Count); // ANCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // NSCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // ARCOUNT

        // Question (echo back)
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";
        var questionStart = data.Count;
        DnsMessageParser.WriteDomainName(data, normalizedZoneName);
        // Store zone name position for compression (position where the name starts)
        // Note: DNS compression pointers point to the start of the name, which is questionStart
        nameCompression[normalizedZoneName.ToLowerInvariant()] = questionStart;
        DnsMessageParser.WriteUInt16(data, 252); // AXFR
        DnsMessageParser.WriteUInt16(data, 1); // IN

        // Answers
        foreach (var record in records)
        {
            WriteRecordWithCompression(data, record, nameCompression, normalizedZoneName);
        }

        return data.ToArray();
    }

    public static byte[] BuildQueryResponse(
        DnsMessage request,
        List<FilteredRecord> matchingRecords,
        DnsResponseCode responseCode = DnsResponseCode.NoError)
    {
        var data = new List<byte>();

        // Header
        DnsMessageParser.WriteUInt16(data, request.Id);
        var flags = 0x8000; // Response bit
        flags |= ((int)request.OpCode << 11);
        flags |= 0x0400; // Authoritative Answer
        flags |= (int)responseCode;
        DnsMessageParser.WriteUInt16(data, (ushort)flags);
        DnsMessageParser.WriteUInt16(data, (ushort)request.Questions.Count); // QDCOUNT
        DnsMessageParser.WriteUInt16(data, (ushort)matchingRecords.Count); // ANCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // NSCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // ARCOUNT

        // Questions (echo back)
        foreach (var question in request.Questions)
        {
            DnsMessageParser.WriteDomainName(data, question.Name);
            DnsMessageParser.WriteUInt16(data, (ushort)question.QueryType);
            DnsMessageParser.WriteUInt16(data, (ushort)question.QueryClass);
        }

        // Answers
        foreach (var record in matchingRecords)
        {
            WriteRecord(data, record);
        }

        return data.ToArray();
    }

    private static void WriteRecord(List<byte> data, FilteredRecord record)
    {
        // Write domain name
        DnsMessageParser.WriteDomainName(data, record.DomainName);

        // Write type and class
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordType);
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordClass);

        // Write TTL
        DnsMessageParser.WriteUInt32(data, (uint)record.TimeToLive);

        // Write RDATA based on record type
        var rdata = SerializeRdata(record);
        DnsMessageParser.WriteUInt16(data, (ushort)rdata.Length);
        data.AddRange(rdata);
    }

    private static void WriteRecordWithCompression(
        List<byte> data, 
        FilteredRecord record, 
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        // Write domain name with compression
        var recordName = record.DomainName.TrimEnd('.');
        var normalizedRecordName = recordName.ToLowerInvariant();
        var normalizedZoneName = zoneName.TrimEnd('.').ToLowerInvariant();
        
        // Check if we can compress: if record name equals zone name, use compression pointer
        if (normalizedRecordName == normalizedZoneName && nameCompression.ContainsKey(zoneName.ToLowerInvariant()))
        {
            // Use compression pointer (0xC000 | offset)
            var offset = nameCompression[zoneName.ToLowerInvariant()];
            if (offset < 16384) // Max offset is 16383
            {
                DnsMessageParser.WriteUInt16(data, (ushort)(0xC000 | offset));
            }
            else
            {
                // Fallback to writing full name if offset too large
                DnsMessageParser.WriteDomainName(data, record.DomainName);
            }
        }
        else
        {
            // Write full domain name
            DnsMessageParser.WriteDomainName(data, record.DomainName);
        }

        // Write type and class
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordType);
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordClass);

        // Write TTL
        DnsMessageParser.WriteUInt32(data, (uint)record.TimeToLive);

        // Write RDATA based on record type (with compression support for domain names in RDATA)
        var rdata = SerializeRdataWithCompression(record, nameCompression, zoneName);
        DnsMessageParser.WriteUInt16(data, (ushort)rdata.Length);
        data.AddRange(rdata);
    }

    private static byte[] SerializeRdata(FilteredRecord record)
    {
        if (record.RawRData is { Length: > 0 })
        {
            return record.RawRData.ToArray();
        }
        else if (record.SoaData != null)
        {
            return SerializeSoa(record.SoaData);
        }
        else if (record.NsName != null)
        {
            return SerializeNs(record.NsName);
        }
        else if (record.OriginalRecord != null)
        {
            return SerializeOriginalRecord(record.OriginalRecord);
        }
        return Array.Empty<byte>();
    }

    private static byte[] SerializeRdataWithCompression(
        FilteredRecord record,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        if (record.RawRData is { Length: > 0 })
        {
            return record.RawRData.ToArray();
        }
        else if (record.SoaData != null)
        {
            return SerializeSoaWithCompression(record.SoaData, nameCompression, zoneName);
        }
        else if (record.NsName != null)
        {
            return SerializeNsWithCompression(record.NsName, nameCompression, zoneName);
        }
        else if (record.OriginalRecord != null)
        {
            return SerializeOriginalRecordWithCompression(record.OriginalRecord, nameCompression, zoneName);
        }
        return Array.Empty<byte>();
    }

    /// <summary>
    /// Serializes RDATA for a record with compression support.
    /// Public method for use by IxfrResponseBuilder.
    /// </summary>
    public static byte[] SerializeRdataForRecord(
        FilteredRecord record,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        return SerializeRdataWithCompression(record, nameCompression, zoneName);
    }

    private static byte[] SerializeSoa(SoaRecordData soa)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, soa.MName);
        DnsMessageParser.WriteDomainName(data, soa.RName);
        DnsMessageParser.WriteUInt32(data, soa.Serial);
        DnsMessageParser.WriteUInt32(data, soa.Refresh);
        DnsMessageParser.WriteUInt32(data, soa.Retry);
        DnsMessageParser.WriteUInt32(data, soa.Expire);
        DnsMessageParser.WriteUInt32(data, soa.Minimum);
        return data.ToArray();
    }

    private static byte[] SerializeNs(string nsName)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, nsName);
        return data.ToArray();
    }

    private static byte[] SerializeOriginalRecord(DnsResourceRecord record)
    {
        // First, try to get raw RDATA using reflection (most reliable for unknown types)
        var rawRdata = TryGetRawRdata(record);
        if (rawRdata != null && rawRdata.Length > 0)
        {
            return rawRdata;
        }

        // Otherwise, serialize based on known record types
        return record switch
        {
            SoaRecord soa => SerializeSoaFromRecord(soa),
            NsRecord ns => SerializeNsFromRecord(ns),
            ARecord a => SerializeA(a),
            AaaaRecord aaaa => SerializeAaaa(aaaa),
            MxRecord mx => SerializeMx(mx),
            CNameRecord cname => SerializeCname(cname),
            TxtRecord txt => SerializeTxt(txt),
            SrvRecord srv => SerializeSrv(srv),
            PtrRecord ptr => SerializePtr(ptr),
            CaaRecord caa => SerializeCaa(caa),
            _ => Array.Empty<byte>() // Unknown type - TryGetRawRdata should have handled it, but if not, return empty
        };
    }

    /// <summary>
    /// Attempts to extract raw RDATA from DnsResourceRecord using reflection.
    /// This allows handling any DNS record type, even if not explicitly implemented.
    /// </summary>
    private static byte[]? TryGetRawRdata(DnsResourceRecord record)
    {
        try
        {
            // Try to access the Raw property if it exists
            var rawProperty = record.GetType().GetProperty("Raw", BindingFlags.Public | BindingFlags.Instance);
            if (rawProperty != null && rawProperty.PropertyType == typeof(byte[]))
            {
                var rawValue = rawProperty.GetValue(record) as byte[];
                if (rawValue != null && rawValue.Length > 0)
                {
                    return rawValue;
                }
            }

            // Try to access internal/private fields that might contain raw RDATA
            var fields = record.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public);
            foreach (var field in fields)
            {
                if ((field.Name.Contains("Raw") || field.Name.Contains("Rdata") || field.Name.Contains("Data")) 
                    && field.FieldType == typeof(byte[]))
                {
                    var value = field.GetValue(record) as byte[];
                    if (value != null && value.Length > 0)
                    {
                        return value;
                    }
                }
            }

            // Try to access via base class
            var baseType = record.GetType().BaseType;
            while (baseType != null && baseType != typeof(object))
            {
                var baseRawProperty = baseType.GetProperty("Raw", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                if (baseRawProperty != null && baseRawProperty.PropertyType == typeof(byte[]))
                {
                    var rawValue = baseRawProperty.GetValue(record) as byte[];
                    if (rawValue != null && rawValue.Length > 0)
                    {
                        return rawValue;
                    }
                }
                baseType = baseType.BaseType;
            }
        }
        catch
        {
            // Reflection failed, fall back to type-specific serialization
        }

        return null;
    }

    private static byte[] SerializeSoaFromRecord(SoaRecord soa)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, soa.MName.Value);
        DnsMessageParser.WriteDomainName(data, soa.RName.Value);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Serial);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Refresh);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Retry);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Expire);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Minimum);
        return data.ToArray();
    }

    private static byte[] SerializeNsFromRecord(NsRecord ns)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, ns.NSDName.Value);
        return data.ToArray();
    }

    private static byte[] SerializeA(ARecord a)
    {
        var data = new List<byte>();
        data.AddRange(a.Address.GetAddressBytes());
        return data.ToArray();
    }

    private static byte[] SerializeAaaa(AaaaRecord aaaa)
    {
        var data = new List<byte>();
        data.AddRange(aaaa.Address.GetAddressBytes());
        return data.ToArray();
    }

    private static byte[] SerializeMx(MxRecord mx)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, (ushort)mx.Preference);
        DnsMessageParser.WriteDomainName(data, mx.Exchange.Value);
        return data.ToArray();
    }

    private static byte[] SerializeCname(CNameRecord cname)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, cname.CanonicalName.Value);
        return data.ToArray();
    }

    private static byte[] SerializeTxt(TxtRecord txt)
    {
        var data = new List<byte>();
        // TXT records: concatenate all text strings, each prefixed with length
        foreach (var text in txt.Text)
        {
            var bytes = Encoding.UTF8.GetBytes(text);
            data.Add((byte)bytes.Length);
            data.AddRange(bytes);
        }
        return data.ToArray();
    }

    private static byte[] SerializeSrv(SrvRecord srv)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Priority);
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Weight);
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Port);
        DnsMessageParser.WriteDomainName(data, srv.Target.Value);
        return data.ToArray();
    }

    private static byte[] SerializePtr(PtrRecord ptr)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, ptr.PtrDomainName.Value);
        return data.ToArray();
    }

    private static byte[] SerializeCaa(CaaRecord caa)
    {
        // RFC 6844: CAA record format
        // 1 byte: flags (unsigned 8-bit integer)
        // Variable length: tag (ASCII string, length-prefixed)
        // Variable length: value (binary data, length-prefixed)
        var data = new List<byte>();
        
        // Flags (1 byte)
        data.Add((byte)caa.Flags);
        
        // Tag (length-prefixed ASCII string)
        var tagBytes = Encoding.ASCII.GetBytes(caa.Tag);
        data.Add((byte)tagBytes.Length);
        data.AddRange(tagBytes);
        
        // Value (length-prefixed binary data)
        // CAA value is stored as a string in DnsClient, but RFC allows binary
        // We'll encode it as UTF-8 bytes
        var valueBytes = Encoding.UTF8.GetBytes(caa.Value);
        data.Add((byte)valueBytes.Length);
        data.AddRange(valueBytes);
        
        return data.ToArray();
    }

    private static byte[] SerializeSoaWithCompression(
        SoaRecordData soa,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, soa.MName, nameCompression, zoneName);
        WriteDomainNameWithCompression(data, soa.RName, nameCompression, zoneName);
        DnsMessageParser.WriteUInt32(data, soa.Serial);
        DnsMessageParser.WriteUInt32(data, soa.Refresh);
        DnsMessageParser.WriteUInt32(data, soa.Retry);
        DnsMessageParser.WriteUInt32(data, soa.Expire);
        DnsMessageParser.WriteUInt32(data, soa.Minimum);
        return data.ToArray();
    }

    private static byte[] SerializeNsWithCompression(
        string nsName,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, nsName, nameCompression, zoneName);
        return data.ToArray();
    }

    private static byte[] SerializeOriginalRecordWithCompression(
        DnsResourceRecord record,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        // First, try to get raw RDATA using reflection (most reliable for unknown types)
        var rawRdata = TryGetRawRdata(record);
        if (rawRdata != null && rawRdata.Length > 0)
        {
            return rawRdata;
        }

        // Otherwise, serialize based on known record types with compression
        return record switch
        {
            SoaRecord soa => SerializeSoaFromRecordWithCompression(soa, nameCompression, zoneName),
            NsRecord ns => SerializeNsFromRecordWithCompression(ns, nameCompression, zoneName),
            ARecord a => SerializeA(a),
            AaaaRecord aaaa => SerializeAaaa(aaaa),
            MxRecord mx => SerializeMxWithCompression(mx, nameCompression, zoneName),
            CNameRecord cname => SerializeCnameWithCompression(cname, nameCompression, zoneName),
            TxtRecord txt => SerializeTxt(txt),
            SrvRecord srv => SerializeSrvWithCompression(srv, nameCompression, zoneName),
            PtrRecord ptr => SerializePtrWithCompression(ptr, nameCompression, zoneName),
            CaaRecord caa => SerializeCaa(caa),
            _ => Array.Empty<byte>()
        };
    }

    private static byte[] SerializeSoaFromRecordWithCompression(
        SoaRecord soa,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, soa.MName.Value, nameCompression, zoneName);
        WriteDomainNameWithCompression(data, soa.RName.Value, nameCompression, zoneName);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Serial);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Refresh);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Retry);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Expire);
        DnsMessageParser.WriteUInt32(data, (uint)soa.Minimum);
        return data.ToArray();
    }

    private static byte[] SerializeNsFromRecordWithCompression(
        NsRecord ns,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, ns.NSDName.Value, nameCompression, zoneName);
        return data.ToArray();
    }

    private static byte[] SerializeMxWithCompression(
        MxRecord mx,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, (ushort)mx.Preference);
        WriteDomainNameWithCompression(data, mx.Exchange.Value, nameCompression, zoneName);
        return data.ToArray();
    }

    private static byte[] SerializeCnameWithCompression(
        CNameRecord cname,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, cname.CanonicalName.Value, nameCompression, zoneName);
        return data.ToArray();
    }

    private static byte[] SerializeSrvWithCompression(
        SrvRecord srv,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Priority);
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Weight);
        DnsMessageParser.WriteUInt16(data, (ushort)srv.Port);
        WriteDomainNameWithCompression(data, srv.Target.Value, nameCompression, zoneName);
        return data.ToArray();
    }

    private static byte[] SerializePtrWithCompression(
        PtrRecord ptr,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, ptr.PtrDomainName.Value, nameCompression, zoneName);
        return data.ToArray();
    }

    private static void WriteDomainNameWithCompression(
        List<byte> data,
        string name,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var normalizedName = name.TrimEnd('.').ToLowerInvariant();
        var normalizedZoneName = zoneName.TrimEnd('.').ToLowerInvariant();

        // Check if this name matches the zone name and we have a compression pointer
        // This is the most common case in zone transfers - domain names in RDATA matching the zone name
        if (normalizedName == normalizedZoneName && nameCompression.ContainsKey(zoneName.ToLowerInvariant()))
        {
            var offset = nameCompression[zoneName.ToLowerInvariant()];
            if (offset < 16384) // Max offset is 16383
            {
                DnsMessageParser.WriteUInt16(data, (ushort)(0xC000 | offset));
                return;
            }
        }

        // Write full name (no compression for other names to keep it simple and avoid offset tracking issues)
        DnsMessageParser.WriteDomainName(data, name);
    }

}

