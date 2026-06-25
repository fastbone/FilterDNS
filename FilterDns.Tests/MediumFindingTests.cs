using System.Net;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Cache;
using FilterDns.Config;
using FilterDns.Dns;
using FilterDns.Filter;
using FilterDns.Recovery;
using FilterDns.Xfer;
using Microsoft.Extensions.Logging;

namespace FilterDns.Tests;

public class MediumFindingTests
{
    [Fact]
    public void DnsRecordBuilder_SerializesCaaWithoutValueLengthByte()
    {
        var caa = RecordFromOriginal(new CaaRecord(
            new ResourceRecordInfo("example.com.", ResourceRecordType.CAA, QueryClass.IN, 300, 0),
            0,
            "issue",
            "letsencrypt.org"));
        var response = DnsRecordBuilder.BuildQueryResponse(
            Query("example.com.", (DnsQueryType)257),
            [caa]);

        var rdata = ExtractFirstAnswerRdata(response);

        Assert.Equal(
            new byte[] { 0, 5, (byte)'i', (byte)'s', (byte)'s', (byte)'u', (byte)'e' }
                .Concat("letsencrypt.org"u8.ToArray()),
            rdata);
    }

    [Fact]
    public void IxfrResponseBuilder_SerializesCaaWithoutValueLengthByte()
    {
        var currentSoa = SoaRecord(serial: 2);
        var oldSoa = SoaRecord(serial: 1);
        var caa = RecordFromOriginal(new CaaRecord(
            new ResourceRecordInfo("example.com.", ResourceRecordType.CAA, QueryClass.IN, 300, 0),
            0,
            "issue",
            "letsencrypt.org"));
        var result = IxfrResponseBuilder.BuildIxfrResponse(
            [
                new ZoneDiff
                {
                    FromSerial = 1,
                    ToSerial = 2,
                    AddedRecords = [caa]
                }
            ],
            currentSoa,
            0x1234,
            new FilterDns.Dns.DnsQuestion
            {
                Name = "example.com.",
                QueryType = DnsQueryType.IXFR,
                QueryClass = DnsQueryClass.IN
            },
            serial => serial == 1 ? oldSoa : currentSoa);

        Assert.True(result.Success, result.FailureReason);
        var caaMessage = result.Messages.Single(message =>
            ExtractAnswerType(message) == (ushort)ResourceRecordType.CAA);
        var rdata = ExtractFirstAnswerRdata(caaMessage);

        Assert.Equal(
            new byte[] { 0, 5, (byte)'i', (byte)'s', (byte)'s', (byte)'u', (byte)'e' }
                .Concat("letsencrypt.org"u8.ToArray()),
            rdata);
    }

    [Fact]
    public async Task ZoneHistoryStorage_SaveDoesNotPruneLiveHistory()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-medium-tests-{Guid.NewGuid():N}");
        var storage = new ZoneHistoryStorage(
            dataDirectory,
            exportBindZoneFiles: false,
            securityConfig: new SecurityConfig { MaxZoneVersionsPerZone = 1 });
        var history = new ZoneHistory("example.com");
        history.AddVersion(1, [SoaRecord(1)]);
        history.AddVersion(2, [SoaRecord(2)]);

        await storage.SaveAsync(history);

        Assert.True(history.HasVersion(1));
        Assert.True(history.HasVersion(2));
    }

    [Fact]
    public void ConfigurationValidator_RejectsInvalidLogLevel()
    {
        var config = ValidConfig();
        config.Server.Logging = new LoggingConfig { DefaultLevel = "Info" };

        Assert.Throws<InvalidOperationException>(() => ConfigurationValidator.Validate(config));
    }

    [Fact]
    public void ConfigurationValidator_RejectsDuplicateZoneNamesAfterNormalization()
    {
        var config = ValidConfig();
        config.Zones.Add(new ZoneConfig
        {
            Name = "Example.COM.",
            Upstream = "127.0.0.1:53",
            Ns1 = "ns1.example.com",
            Ns2 = "ns2.example.com"
        });

        Assert.Throws<InvalidOperationException>(() => ConfigurationValidator.Validate(config));
    }

    [Fact]
    public void ConfigurationValidator_RejectsInvalidPrivateIpRange()
    {
        var config = ValidConfig();
        config.Zones[0].PrivateIPRanges = ["192.168.1.0/99"];

        Assert.Throws<InvalidOperationException>(() => ConfigurationValidator.Validate(config));
    }

    [Fact]
    public void XferHandler_CalculatesExactAxfrTransferSizeBeforeStreaming()
    {
        var method = typeof(XferHandler).GetMethod(
            "CalculateAxfrTransferSizeBytes",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        var records = new List<FilteredRecord>
        {
            SoaRecord(1),
            new()
            {
                DomainName = "large.example.com.",
                RecordType = ResourceRecordType.TXT,
                RecordClass = QueryClass.IN,
                TimeToLive = 300,
                RawRData = Enumerable.Repeat((byte)'a', 220).Prepend((byte)220).ToArray()
            }
        };

        var exactSize = Assert.IsType<long>(method.Invoke(null, [records, (ushort)0x1234, "example.com"]));

        Assert.True(exactSize > records.Count * 100L);
    }

    [Fact]
    public void XferHandler_ChoosesNotifyResponseAfterZoneAndSourceValidation()
    {
        var method = typeof(XferHandler).GetMethod(
            "GetNotifyResponseCode",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);
        var zones = new Dictionary<string, (ZoneConfig Config, FilterDns.Whitelist.IpWhitelist Whitelist)>
        {
            ["example.com"] = (
                new ZoneConfig
                {
                    Name = "example.com",
                    Upstream = "192.0.2.1:53",
                    Ns1 = "ns1.example.com",
                    Ns2 = "ns2.example.com"
                },
                new FilterDns.Whitelist.IpWhitelist([]))
        };

        Assert.Equal(
            FilterDns.Dns.DnsResponseCode.NoError,
            method.Invoke(null, [zones, "example.com", IPAddress.Parse("192.0.2.1")]));
        Assert.Equal(
            FilterDns.Dns.DnsResponseCode.Refused,
            method.Invoke(null, [zones, "example.com", IPAddress.Parse("192.0.2.2")]));
        Assert.Equal(
            FilterDns.Dns.DnsResponseCode.Refused,
            method.Invoke(null, [zones, "missing.example", IPAddress.Parse("192.0.2.1")]));
    }

    [Fact]
    public void XferHandler_BuildsServFailResponseForUdpSaturation()
    {
        var method = typeof(XferHandler).GetMethod(
            "BuildUdpSaturationResponse",
            System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(method);

        var response = Assert.IsType<byte[]>(method.Invoke(null, [new byte[] { 0x12, 0x34 }]));

        Assert.Equal(0x12, response[0]);
        Assert.Equal(0x34, response[1]);
        Assert.Equal((byte)FilterDns.Dns.DnsResponseCode.ServFail, (byte)(response[3] & 0x0F));
    }

    [Fact]
    public void SelfRestartService_SuppressesRestartWhenWindowLimitReached()
    {
        var now = new DateTime(2026, 6, 25, 0, 0, 0, DateTimeKind.Utc);
        var exits = 0;
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new SelfRestartService(
            new SelfRestartConfig
            {
                MinimumUptimeBeforeRestartSeconds = 0,
                MaxRestartsInWindow = 1,
                RestartWindowSeconds = 3600
            },
            loggerFactory.CreateLogger<SelfRestartService>(),
            exitAction: _ => exits++,
            utcNow: () => now,
            existingRestartAttempts: [now.AddMinutes(-5)]);

        service.TriggerRestart("test");

        Assert.False(service.IsRestartTriggered);
        Assert.Equal(0, exits);
    }

    [Fact]
    public void SelfRestartService_LoadsRestartWindowFromPersistedHistory()
    {
        var now = new DateTime(2026, 6, 25, 0, 0, 0, DateTimeKind.Utc);
        var historyPath = Path.Combine(Path.GetTempPath(), $"filterdns-restarts-{Guid.NewGuid():N}.txt");
        File.WriteAllLines(historyPath, [now.AddMinutes(-5).ToString("O")]);
        var exits = 0;
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var service = new SelfRestartService(
            new SelfRestartConfig
            {
                MinimumUptimeBeforeRestartSeconds = 0,
                MaxRestartsInWindow = 1,
                RestartWindowSeconds = 3600
            },
            loggerFactory.CreateLogger<SelfRestartService>(),
            exitAction: _ => exits++,
            utcNow: () => now,
            restartHistoryFilePath: historyPath);

        service.TriggerRestart("test");

        Assert.False(service.IsRestartTriggered);
        Assert.Equal(0, exits);
    }

    [Fact]
    public void DnsProxyServer_ConfiguresSelfRestartHistoryUnderDataDirectory()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"filterdns-restart-data-{Guid.NewGuid():N}");
        using var loggerFactory = LoggerFactory.Create(_ => { });
        var config = ValidConfig();
        config.Server.DataDirectory = dataDirectory;
        var proxy = new FilterDns.Proxy.DnsProxyServer(
            config,
            loggerFactory.CreateLogger<FilterDns.Proxy.DnsProxyServer>(),
            loggerFactory);

        var restartService = GetPrivateField<SelfRestartService>(proxy, "_selfRestartService");
        var restartHistoryPath = GetPrivateField<string>(restartService, "_restartHistoryFilePath");

        Assert.Equal(Path.Combine(dataDirectory, "self-restart-history.txt"), restartHistoryPath);
    }

    private static DnsMessage Query(string name, DnsQueryType type)
    {
        return new DnsMessage
        {
            Id = 0x1234,
            Questions =
            [
                new FilterDns.Dns.DnsQuestion
                {
                    Name = name,
                    QueryType = type,
                    QueryClass = DnsQueryClass.IN
                }
            ]
        };
    }

    private static AppConfiguration ValidConfig()
    {
        return new AppConfiguration
        {
            Server = new ServerConfig
            {
                ListenAddress = "127.0.0.1",
                ListenPort = 5353,
                LogLevel = "Information",
                HealthCheckAcl = ["127.0.0.1"],
                Logging = new LoggingConfig()
            },
            Zones =
            [
                new ZoneConfig
                {
                    Name = "example.com",
                    Upstream = "127.0.0.1:53",
                    Ns1 = "ns1.example.com",
                    Ns2 = "ns2.example.com",
                    PrivateIPRanges = ["10.0.0.0/8"],
                    Slaves = [new SlaveConfig { Ip = "127.0.0.1", Port = 53 }],
                    XferWhitelist = ["127.0.0.1"]
                }
            ]
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

    private static ushort ExtractAnswerType(byte[] message)
    {
        var offset = 12;
        SkipDomainName(message, ref offset);
        offset += 4;
        SkipDomainName(message, ref offset);
        return ReadUInt16(message, ref offset);
    }

    private static byte[] ExtractFirstAnswerRdata(byte[] message)
    {
        var offset = 12;
        SkipDomainName(message, ref offset);
        offset += 4;
        SkipDomainName(message, ref offset);
        offset += 2;
        offset += 2;
        offset += 4;
        var rdLength = ReadUInt16(message, ref offset);
        return message.Skip(offset).Take(rdLength).ToArray();
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

    private static T GetPrivateField<T>(object instance, string fieldName)
    {
        var field = instance.GetType().GetField(fieldName, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Assert.NotNull(field);
        return Assert.IsType<T>(field.GetValue(instance));
    }
}
