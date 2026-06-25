using System.Net;
using System.Net.Sockets;
using System.Text;
using DnsClient.Protocol;

namespace FilterDns.Dns;

public class DnsZoneTransfer
{
    public static async Task<List<DnsResourceRecord>> FetchZoneAsync(
        string upstream,
        string zoneName,
        CancellationToken cancellationToken = default)
    {
        var parts = upstream.Split(':');
        var ip = IPAddress.Parse(parts[0]);
        var port = parts.Length > 1 ? int.Parse(parts[1]) : 53;
        var endpoint = new IPEndPoint(ip, port);

        var records = new List<DnsResourceRecord>();

        using var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(endpoint, cancellationToken);
        var stream = tcpClient.GetStream();

        // Build AXFR query
        var query = BuildAxfrQuery(zoneName);
        var queryLength = (ushort)query.Length;

        // Send length prefix + query
        await stream.WriteAsync(new[] { (byte)(queryLength >> 8), (byte)(queryLength & 0xFF) }, cancellationToken);
        await stream.WriteAsync(query, cancellationToken);
        await stream.FlushAsync(cancellationToken);

        // Read responses until we get the final SOA
        bool gotFinalSoa = false;
        while (!gotFinalSoa && !cancellationToken.IsCancellationRequested)
        {
            // Read length prefix
            var lenBuffer = new byte[2];
            await stream.ReadExactlyAsync(lenBuffer, cancellationToken);
            var responseLength = (lenBuffer[0] << 8) | lenBuffer[1];

            // Read response
            var responseBuffer = new byte[responseLength];
            await stream.ReadExactlyAsync(responseBuffer, cancellationToken);

            // Parse response and extract records
            var parsedRecords = ParseZoneTransferResponse(responseBuffer, zoneName);
            records.AddRange(parsedRecords);

            // Check if we got the final SOA (last record in transfer)
            if (parsedRecords.Any(r => r.RecordType == ResourceRecordType.SOA))
            {
                // If this is the second SOA, we're done
                var soaCount = records.Count(r => r.RecordType == ResourceRecordType.SOA);
                if (soaCount >= 2)
                {
                    gotFinalSoa = true;
                }
            }
        }

        return records;
    }

    private static byte[] BuildAxfrQuery(string zoneName)
    {
        var data = new List<byte>();
        // Use Random.Shared for thread-safe, non-predictable random number generation
        var id = (ushort)Random.Shared.Next(0, 65535);

        // Header
        DnsMessageParser.WriteUInt16(data, id);
        DnsMessageParser.WriteUInt16(data, 0x0100); // Standard query, recursion desired
        DnsMessageParser.WriteUInt16(data, 1); // QDCOUNT = 1
        DnsMessageParser.WriteUInt16(data, 0); // ANCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // NSCOUNT
        DnsMessageParser.WriteUInt16(data, 0); // ARCOUNT

        // Question
        DnsMessageParser.WriteDomainName(data, zoneName.EndsWith('.') ? zoneName : $"{zoneName}.");
        DnsMessageParser.WriteUInt16(data, 252); // AXFR
        DnsMessageParser.WriteUInt16(data, 1); // IN

        return data.ToArray();
    }

    private static List<DnsResourceRecord> ParseZoneTransferResponse(byte[] data, string zoneName)
    {
        // Simplified parsing - would need full DNS record parsing
        // For now, return empty list - this needs proper DNS record parsing implementation
        return new List<DnsResourceRecord>();
    }
}



