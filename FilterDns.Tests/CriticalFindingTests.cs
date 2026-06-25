using System.Net;
using System.IO.Compression;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Cache;
using FilterDns.Config;
using FilterDns.Dns;
using FilterDns.Filter;
using FilterDns.Whitelist;
using FilterDns.Xfer;

namespace FilterDns.Tests;

public class CriticalFindingTests
{
    [Fact]
    public void IpWhitelist_AllowsAddressesInsideNonByteAlignedIpv4Cidr()
    {
        var whitelist = new IpWhitelist(["192.168.1.0/25"]);

        Assert.True(whitelist.Allows(IPAddress.Parse("192.168.1.0")));
        Assert.True(whitelist.Allows(IPAddress.Parse("192.168.1.1")));
        Assert.True(whitelist.Allows(IPAddress.Parse("192.168.1.64")));
        Assert.False(whitelist.Allows(IPAddress.Parse("192.168.1.128")));
    }

    [Fact]
    public void RecordFilter_FiltersCustomNonByteAlignedPrivateIpv6Range()
    {
        var config = new ZoneConfig
        {
            Name = "example.com",
            Ns1 = "ns1.example.com",
            Ns2 = "ns2.example.com",
            FilterPrivateIPs = true,
            PrivateIPRanges = ["fc00::/7"]
        };
        var records = new DnsResourceRecord[]
        {
            new AaaaRecord(
                new ResourceRecordInfo("secret.example.com.", ResourceRecordType.AAAA, QueryClass.IN, 300, 16),
                IPAddress.Parse("fd00::1"))
        };

        var filtered = RecordFilter.ApplyFilters(records, config, "example.com");

        Assert.DoesNotContain(filtered, record => record.DomainName == "secret.example.com.");
    }

    [Fact]
    public async Task ZoneHistoryStorage_RoundTripsARecordRdataForLoadedHistory()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-tests-{Guid.NewGuid():N}");
        var storage = new ZoneHistoryStorage(dataDirectory, exportBindZoneFiles: false);
        var history = new ZoneHistory("example.com");
        var record = new FilteredRecord
        {
            DomainName = "www.example.com.",
            RecordType = ResourceRecordType.A,
            RecordClass = QueryClass.IN,
            TimeToLive = 300,
            OriginalRecord = new ARecord(
                new ResourceRecordInfo("www.example.com.", ResourceRecordType.A, QueryClass.IN, 300, 4),
                IPAddress.Parse("203.0.113.10"))
        };
        history.AddVersion(1, [record]);

        await storage.SaveAsync(history);
        var loaded = await storage.LoadAsync("example.com");
        var loadedRecord = Assert.Single(loaded!.GetVersion(1)!.Records);

        var response = DnsRecordBuilder.BuildQueryResponse(
            new DnsMessage
            {
                Id = 0x1234,
                Questions =
                [
                    new FilterDns.Dns.DnsQuestion
                    {
                        Name = "www.example.com.",
                        QueryType = DnsQueryType.A,
                        QueryClass = DnsQueryClass.IN
                    }
                ]
            },
            [loadedRecord]);

        var rdata = ExtractFirstAnswerRdata(response);
        Assert.Equal(IPAddress.Parse("203.0.113.10").GetAddressBytes(), rdata);
    }

    [Fact]
    public async Task ZoneHistoryStorage_RoundTripsCommonRecordTypeRdataForLoadedHistory()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-tests-{Guid.NewGuid():N}");
        var storage = new ZoneHistoryStorage(dataDirectory, exportBindZoneFiles: false);
        var records = new List<FilteredRecord>
        {
            RecordFromOriginal(
                new AaaaRecord(
                    new ResourceRecordInfo("v6.example.com.", ResourceRecordType.AAAA, QueryClass.IN, 300, 16),
                    IPAddress.Parse("2001:db8::10"))),
            RecordFromOriginal(
                new MxRecord(
                    new ResourceRecordInfo("example.com.", ResourceRecordType.MX, QueryClass.IN, 300, 0),
                    10,
                    DnsString.Parse("mail.example.com."))),
            RecordFromOriginal(
                new TxtRecord(
                    new ResourceRecordInfo("txt.example.com.", ResourceRecordType.TXT, QueryClass.IN, 300, 0),
                    ["hello"],
                    ["hello"])),
            RecordFromOriginal(
                new CNameRecord(
                    new ResourceRecordInfo("alias.example.com.", ResourceRecordType.CNAME, QueryClass.IN, 300, 0),
                    DnsString.Parse("www.example.com."))),
            RecordFromOriginal(
                new CaaRecord(
                    new ResourceRecordInfo("example.com.", ResourceRecordType.CAA, QueryClass.IN, 300, 0),
                    0,
                    "issue",
                    "letsencrypt.org")),
            new()
            {
                DomainName = "example.com.",
                RecordType = ResourceRecordType.SOA,
                RecordClass = QueryClass.IN,
                TimeToLive = 300,
                SoaData = new SoaRecordData
                {
                    MName = "ns1.example.com.",
                    RName = "admin.example.com.",
                    Serial = 1,
                    Refresh = 3600,
                    Retry = 600,
                    Expire = 604800,
                    Minimum = 300
                }
            },
            new()
            {
                DomainName = "example.com.",
                RecordType = ResourceRecordType.NS,
                RecordClass = QueryClass.IN,
                TimeToLive = 300,
                NsName = "ns1.example.com."
            }
        };
        var expectedRdata = records.ToDictionary(
            record => $"{record.DomainName}|{record.RecordType}",
            RDataSerializer.Serialize);
        var history = new ZoneHistory("example.com");
        history.AddVersion(1, records);

        await storage.SaveAsync(history);
        var loaded = await storage.LoadAsync("example.com");

        Assert.NotNull(loaded);
        foreach (var loadedRecord in loaded.GetVersion(1)!.Records)
        {
            Assert.Equal(
                expectedRdata[$"{loadedRecord.DomainName}|{loadedRecord.RecordType}"],
                RDataSerializer.Serialize(loadedRecord));
        }
    }

    [Fact]
    public async Task ZoneHistoryStorage_RejectsUnsupportedRecordWithoutSerializableRdataOnSave()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-tests-{Guid.NewGuid():N}");
        var storage = new ZoneHistoryStorage(dataDirectory, exportBindZoneFiles: false);
        var history = new ZoneHistory("example.com");
        history.AddVersion(1,
        [
            new FilteredRecord
            {
                DomainName = "unknown.example.com.",
                RecordType = (ResourceRecordType)65000,
                RecordClass = QueryClass.IN,
                TimeToLive = 300
            }
        ]);

        await Assert.ThrowsAsync<InvalidOperationException>(() => storage.SaveAsync(history));
    }

    [Fact]
    public async Task ZoneHistoryStorage_RejectsLegacyHistoryWithoutRequiredRdata()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-tests-{Guid.NewGuid():N}");
        var historyDirectory = Path.Combine(dataDirectory, "history");
        Directory.CreateDirectory(historyDirectory);
        var historyFilePath = Path.Combine(historyDirectory, "example_com.json");
        await File.WriteAllTextAsync(
            historyFilePath,
            """
            [
              {
                "serial": 1,
                "timestamp": "2026-06-25T00:00:00Z",
                "records": [
                  {
                    "domainName": "www.example.com.",
                    "recordType": 1,
                    "recordClass": 1,
                    "timeToLive": 300
                  }
                ]
              }
            ]
            """);
        var storage = new ZoneHistoryStorage(dataDirectory, exportBindZoneFiles: false);

        var loaded = await storage.LoadAsync("example.com");

        Assert.Null(loaded);
        Assert.False(File.Exists(historyFilePath));
        var archivePath = Assert.Single(Directory.GetFiles(Path.Combine(historyDirectory, "invalid"), "example_com_*.zip"));
        using var archive = ZipFile.OpenRead(archivePath);
        Assert.Contains(archive.Entries, entry => entry.FullName == "example_com.json");
        Assert.Contains(archive.Entries, entry => entry.FullName == "reason.txt");
    }

    [Fact]
    public void ZoneDiffCalculator_TreatsTtlChangeAsDeleteAndAdd()
    {
        var oldRecord = new FilteredRecord
        {
            DomainName = "www.example.com.",
            RecordType = ResourceRecordType.A,
            RecordClass = QueryClass.IN,
            TimeToLive = 300,
            OriginalRecord = new ARecord(
                new ResourceRecordInfo("www.example.com.", ResourceRecordType.A, QueryClass.IN, 300, 4),
                IPAddress.Parse("203.0.113.10"))
        };
        var newRecord = new FilteredRecord
        {
            DomainName = "www.example.com.",
            RecordType = ResourceRecordType.A,
            RecordClass = QueryClass.IN,
            TimeToLive = 600,
            OriginalRecord = new ARecord(
                new ResourceRecordInfo("www.example.com.", ResourceRecordType.A, QueryClass.IN, 600, 4),
                IPAddress.Parse("203.0.113.10"))
        };

        var diff = ZoneDiffCalculator.CalculateDiff([oldRecord], 1, [newRecord], 2);

        Assert.Single(diff.DeletedRecords);
        Assert.Single(diff.AddedRecords);
    }

    [Fact]
    public void ZoneDiffCalculator_DistinguishesLoadedRecordsByRawRdata()
    {
        var oldRecords = new List<FilteredRecord>
        {
            LoadedARecord("www.example.com.", 300, "203.0.113.10"),
            LoadedARecord("www.example.com.", 300, "203.0.113.11")
        };
        var newRecords = new List<FilteredRecord>
        {
            LoadedARecord("www.example.com.", 300, "203.0.113.10")
        };

        var diff = ZoneDiffCalculator.CalculateDiff(oldRecords, 1, newRecords, 2);

        var deleted = Assert.Single(diff.DeletedRecords);
        Assert.Equal(IPAddress.Parse("203.0.113.11").GetAddressBytes(), deleted.RawRData);
        Assert.Empty(diff.AddedRecords);
    }

    private static byte[] ExtractFirstAnswerRdata(byte[] message)
    {
        var offset = 12;
        SkipDomainName(message, ref offset);
        offset += 4;
        SkipDomainName(message, ref offset);
        offset += 2; // type
        offset += 2; // class
        offset += 4; // ttl
        var rdLength = ReadUInt16(message, ref offset);
        return message.Skip(offset).Take(rdLength).ToArray();
    }

    private static FilteredRecord LoadedARecord(string name, int ttl, string address)
    {
        return new FilteredRecord
        {
            DomainName = name,
            RecordType = ResourceRecordType.A,
            RecordClass = QueryClass.IN,
            TimeToLive = ttl,
            RawRData = IPAddress.Parse(address).GetAddressBytes()
        };
    }

    private static FilteredRecord RecordFromOriginal(DnsResourceRecord record)
    {
        return new FilteredRecord
        {
            DomainName = record.DomainName.Value,
            RecordType = record.RecordType,
            RecordClass = record.RecordClass,
            TimeToLive = record.TimeToLive,
            OriginalRecord = record
        };
    }

    private static void SkipDomainName(byte[] message, ref int offset)
    {
        while (offset < message.Length)
        {
            var length = message[offset++];
            if (length == 0)
            {
                return;
            }

            if ((length & 0xC0) == 0xC0)
            {
                offset++;
                return;
            }

            offset += length;
        }
    }

    private static ushort ReadUInt16(byte[] message, ref int offset)
    {
        var value = (ushort)((message[offset] << 8) | message[offset + 1]);
        offset += 2;
        return value;
    }
}
