using System.Reflection;
using System.Text;
using DnsClient.Protocol;
using FilterDns.Filter;

namespace FilterDns.Dns;

public static class RDataSerializer
{
    public static byte[] Serialize(FilteredRecord record)
    {
        if (record.RawRData is { Length: > 0 })
        {
            return record.RawRData.ToArray();
        }

        if (record.SoaData != null)
        {
            return SerializeSoa(record.SoaData);
        }

        if (record.NsName != null)
        {
            return SerializeDomainName(record.NsName);
        }

        if (record.OriginalRecord == null)
        {
            return Array.Empty<byte>();
        }

        return Serialize(record.OriginalRecord);
    }

    public static byte[] Serialize(DnsResourceRecord record)
    {
        var rawRdata = TryGetRawRdata(record);
        if (rawRdata is { Length: > 0 })
        {
            return rawRdata;
        }

        return record switch
        {
            SoaRecord soa => SerializeSoa(soa),
            NsRecord ns => SerializeDomainName(ns.NSDName.Value),
            ARecord a => a.Address.GetAddressBytes(),
            AaaaRecord aaaa => aaaa.Address.GetAddressBytes(),
            MxRecord mx => SerializeMx(mx),
            CNameRecord cname => SerializeDomainName(cname.CanonicalName.Value),
            TxtRecord txt => SerializeTxt(txt),
            SrvRecord srv => SerializeSrv(srv),
            PtrRecord ptr => SerializeDomainName(ptr.PtrDomainName.Value),
            CaaRecord caa => SerializeCaa(caa),
            _ => Array.Empty<byte>()
        };
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

    private static byte[] SerializeSoa(SoaRecord soa)
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

    private static byte[] SerializeMx(MxRecord mx)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, (ushort)mx.Preference);
        DnsMessageParser.WriteDomainName(data, mx.Exchange.Value);
        return data.ToArray();
    }

    private static byte[] SerializeTxt(TxtRecord txt)
    {
        var data = new List<byte>();
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

    private static byte[] SerializeCaa(CaaRecord caa)
    {
        var data = new List<byte>();
        data.Add((byte)caa.Flags);
        var tagBytes = Encoding.ASCII.GetBytes(caa.Tag);
        data.Add((byte)tagBytes.Length);
        data.AddRange(tagBytes);
        data.AddRange(Encoding.UTF8.GetBytes(caa.Value));
        return data.ToArray();
    }

    private static byte[] SerializeDomainName(string name)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, name);
        return data.ToArray();
    }

    private static byte[]? TryGetRawRdata(DnsResourceRecord record)
    {
        try
        {
            var rawProperty = record.GetType().GetProperty("Raw", BindingFlags.Public | BindingFlags.Instance);
            if (rawProperty?.PropertyType == typeof(byte[]))
            {
                var rawValue = rawProperty.GetValue(record) as byte[];
                if (rawValue is { Length: > 0 })
                {
                    return rawValue;
                }
            }

            var fields = record.GetType().GetFields(BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Public);
            foreach (var field in fields)
            {
                if ((field.Name.Contains("Raw") || field.Name.Contains("Rdata") || field.Name.Contains("Data"))
                    && field.FieldType == typeof(byte[]))
                {
                    var value = field.GetValue(record) as byte[];
                    if (value is { Length: > 0 })
                    {
                        return value;
                    }
                }
            }

            var baseType = record.GetType().BaseType;
            while (baseType != null && baseType != typeof(object))
            {
                var baseRawProperty = baseType.GetProperty("Raw", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                if (baseRawProperty?.PropertyType == typeof(byte[]))
                {
                    var rawValue = baseRawProperty.GetValue(record) as byte[];
                    if (rawValue is { Length: > 0 })
                    {
                        return rawValue;
                    }
                }
                baseType = baseType.BaseType;
            }
        }
        catch
        {
            return null;
        }

        return null;
    }
}
