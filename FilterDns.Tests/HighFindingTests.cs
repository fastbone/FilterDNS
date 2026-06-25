using System.Net;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Cache;
using FilterDns.Config;
using FilterDns.Dns;
using FilterDns.Filter;
using FilterDns.Proxy;
using FilterDns.Xfer;
using Microsoft.Extensions.Logging;

namespace FilterDns.Tests;

public class HighFindingTests
{
    [Fact]
    public void DnsMessageParser_ParsesCompressedAuthoritySoaWithHardening()
    {
        var message = BuildIxfrRequestWithCompressedAuthoritySoa(clientSerial: 42);

        var parsed = DnsMessageParser.Parse(message);
        var serial = DnsMessageParser.ExtractIxfrClientSerial(parsed, message);

        var authority = Assert.Single(parsed.Authority);
        Assert.Equal(ResourceRecordType.SOA, authority.RecordType);
        Assert.Equal((uint)42, serial);
    }

    [Fact]
    public void ZoneDiffCalculator_UsesSnapshotDictionaryInsteadOfLiveHistory()
    {
        var history = new ZoneHistory("example.com");
        history.AddVersion(1, [ARecord("www.example.com.", 300, "203.0.113.1")]);
        history.AddVersion(2, [ARecord("www.example.com.", 300, "203.0.113.2")]);
        var snapshot = history.GetAllVersions();
        history.Clear();

        var diffs = ZoneDiffCalculator.CalculateDiffSequence(
            snapshot,
            fromSerial: 1,
            toSerial: 2);

        var diff = Assert.Single(diffs);
        Assert.Equal(1u, diff.FromSerial);
        Assert.Equal(2u, diff.ToSerial);
        Assert.Single(diff.DeletedRecords);
        Assert.Single(diff.AddedRecords);
    }

    [Fact]
    public void ZoneDiffCalculator_PreservesSnapshotSerialWraparoundOrder()
    {
        var snapshot = new Dictionary<uint, ZoneVersion>
        {
            [uint.MaxValue] = new()
            {
                Serial = uint.MaxValue,
                Records = [ARecord("www.example.com.", 300, "203.0.113.255")]
            },
            [0] = new()
            {
                Serial = 0,
                Records = [ARecord("www.example.com.", 300, "203.0.113.0")]
            },
            [1] = new()
            {
                Serial = 1,
                Records = [ARecord("www.example.com.", 300, "203.0.113.1")]
            }
        };

        var diffs = ZoneDiffCalculator.CalculateDiffSequence(snapshot, uint.MaxValue, 1);

        Assert.Collection(
            diffs,
            diff =>
            {
                Assert.Equal(uint.MaxValue, diff.FromSerial);
                Assert.Equal(0u, diff.ToSerial);
            },
            diff =>
            {
                Assert.Equal(0u, diff.FromSerial);
                Assert.Equal(1u, diff.ToSerial);
            });
    }

    [Fact]
    public async Task TransferRefresh_DoesNotDowngradeNewerCachedSerial()
    {
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var proxy = CreateProxy(loggerFactory, minimumZoneRecordCount: 0);
        var cache = GetPrivateField<ZoneCache>(proxy, "_cache");
        cache.UpdateZone("example.com", ZoneRecords(serial: 3));

        await InvokeTransferRefreshAsync(proxy, ZoneRecords(serial: 2));

        Assert.Equal((uint)3, cache.GetSerial("example.com"));
    }

    [Fact]
    public async Task TransferRefresh_AllowsWrappedSerialAfterUintMax()
    {
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var proxy = CreateProxy(loggerFactory, minimumZoneRecordCount: 0);
        var cache = GetPrivateField<ZoneCache>(proxy, "_cache");
        cache.UpdateZone("example.com", ZoneRecords(serial: uint.MaxValue));

        await InvokeTransferRefreshAsync(proxy, ZoneRecords(serial: 1));

        Assert.Equal((uint)1, cache.GetSerial("example.com"));
    }

    [Fact]
    public void XferHandler_TreatsWrappedUpstreamSerialAsNewer()
    {
        var method = typeof(XferHandler).GetMethod(
            "IsSerialNewer",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);

        Assert.True((bool)method.Invoke(null, [1u, uint.MaxValue])!);
        Assert.False((bool)method.Invoke(null, [uint.MaxValue, 1u])!);
    }

    [Fact]
    public void DnsProxyServer_OnlyFetchesWhenUpstreamSerialIsNewer()
    {
        var method = typeof(DnsProxyServer).GetMethod(
            "ShouldFetchFromUpstream",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);

        Assert.False((bool)method.Invoke(null, [3u, true, 2u])!);
        Assert.True((bool)method.Invoke(null, [uint.MaxValue, true, 1u])!);
        Assert.True((bool)method.Invoke(null, [3u, false, 2u])!);
    }

    [Fact]
    public async Task TransferRefresh_DoesNotCacheZoneBelowMinimumRecordCount()
    {
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var proxy = CreateProxy(loggerFactory, minimumZoneRecordCount: 3);
        var cache = GetPrivateField<ZoneCache>(proxy, "_cache");

        await InvokeTransferRefreshAsync(proxy, [SoaRecord(serial: 2)]);

        Assert.Null(cache.GetZone("example.com"));
    }

    [Fact]
    public void DnsProxyServer_NormalizesConfiguredZoneNamesForExternalLookups()
    {
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var proxy = CreateProxy(loggerFactory, zoneName: "Example.COM.");

        var zones = GetPrivateField<Dictionary<string, (ZoneConfig Config, FilterDns.Whitelist.IpWhitelist Whitelist)>>(
            proxy,
            "_zones");

        var entry = Assert.Single(zones);
        Assert.Equal("example.com", entry.Key);
        Assert.Equal("example.com", entry.Value.Config.Name);
    }

    private static FilteredRecord ARecord(string name, int ttl, string address)
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

    private static List<FilteredRecord> ZoneRecords(uint serial)
    {
        return
        [
            SoaRecord(serial),
            new()
            {
                DomainName = "example.com.",
                RecordType = ResourceRecordType.NS,
                RecordClass = QueryClass.IN,
                TimeToLive = 300,
                NsName = "ns1.example.com."
            },
            ARecord("www.example.com.", 300, $"203.0.113.{serial % 250}")
        ];
    }

    private static FilteredRecord SoaRecord(uint serial)
    {
        return new FilteredRecord
        {
            DomainName = "example.com.",
            RecordType = ResourceRecordType.SOA,
            RecordClass = QueryClass.IN,
            TimeToLive = 300,
            SoaData = new SoaRecordData
            {
                MName = "ns1.example.com.",
                RName = "admin.example.com.",
                Serial = serial,
                Refresh = 3600,
                Retry = 600,
                Expire = 604800,
                Minimum = 300
            }
        };
    }

    private static DnsProxyServer CreateProxy(
        ILoggerFactory loggerFactory,
        int minimumZoneRecordCount = 0,
        string zoneName = "example.com")
    {
        return new DnsProxyServer(
            new AppConfiguration
            {
                Server = new ServerConfig
                {
                    DataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-high-tests-{Guid.NewGuid():N}")
                },
                Zones =
                [
                    new ZoneConfig
                    {
                        Name = zoneName,
                        Upstream = "127.0.0.1:5300",
                        Ns1 = "ns1.example.com",
                        Ns2 = "ns2.example.com",
                        MinimumZoneRecordCount = minimumZoneRecordCount
                    }
                ]
            },
            loggerFactory.CreateLogger<DnsProxyServer>(),
            loggerFactory);
    }

    private static async Task InvokeTransferRefreshAsync(DnsProxyServer proxy, List<FilteredRecord> records)
    {
        var method = typeof(DnsProxyServer).GetMethod(
            "HandleZoneUpdatedDuringTransferAsync",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        var zones = GetPrivateField<Dictionary<string, (ZoneConfig Config, FilterDns.Whitelist.IpWhitelist Whitelist)>>(
            proxy,
            "_zones");
        var zoneConfig = zones["example.com"].Config;

        var task = Assert.IsAssignableFrom<Task>(method.Invoke(
            proxy,
            [
                "example.com",
                zoneConfig,
                records,
                records.First(r => r.RecordType == ResourceRecordType.SOA).SoaData!.Serial,
                null,
                0u,
                CancellationToken.None
            ])!);
        await task;
    }

    private static T GetPrivateField<T>(object instance, string fieldName)
    {
        var field = instance.GetType().GetField(fieldName, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(field);
        return Assert.IsType<T>(field.GetValue(instance));
    }

    private static byte[] BuildIxfrRequestWithCompressedAuthoritySoa(uint clientSerial)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteUInt16(data, 0x1234);
        DnsMessageParser.WriteUInt16(data, 0x0000);
        DnsMessageParser.WriteUInt16(data, 1); // QDCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // ANCOUNT
        DnsMessageParser.WriteUInt16(data, 1); // NSCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // ARCOUNT

        DnsMessageParser.WriteDomainName(data, "example.com.");
        DnsMessageParser.WriteUInt16(data, (ushort)DnsQueryType.IXFR);
        DnsMessageParser.WriteUInt16(data, (ushort)DnsQueryClass.IN);

        DnsMessageParser.WriteUInt16(data, 0xC00C); // compressed owner points at question name
        DnsMessageParser.WriteUInt16(data, (ushort)DnsQueryType.SOA);
        DnsMessageParser.WriteUInt16(data, (ushort)DnsQueryClass.IN);
        DnsMessageParser.WriteUInt32(data, 60);

        var rdata = new List<byte>();
        DnsMessageParser.WriteDomainName(rdata, "ns1.example.com.");
        DnsMessageParser.WriteDomainName(rdata, "admin.example.com.");
        DnsMessageParser.WriteUInt32(rdata, clientSerial);
        DnsMessageParser.WriteUInt32(rdata, 3600);
        DnsMessageParser.WriteUInt32(rdata, 600);
        DnsMessageParser.WriteUInt32(rdata, 604800);
        DnsMessageParser.WriteUInt32(rdata, 300);

        DnsMessageParser.WriteUInt16(data, (ushort)rdata.Count);
        data.AddRange(rdata);

        return data.ToArray();
    }
}
