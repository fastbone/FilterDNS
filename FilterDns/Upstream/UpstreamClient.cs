using System.Net;
using DnsClient;
using DnsClient.Protocol;
using FilterDns.Config;

namespace FilterDns.Upstream;

public class UpstreamClient : IDisposable
{
    private readonly string _upstreamAddress;
    private readonly IPEndPoint _endpoint;
    private readonly TimeSpan _timeout;

    public UpstreamClient(string upstream, TimeSpan? timeout = null)
    {
        _upstreamAddress = upstream;
        var parts = upstream.Split(':');
        var ip = IPAddress.Parse(parts[0]);
        var port = parts.Length > 1 ? int.Parse(parts[1]) : 53;
        _endpoint = new IPEndPoint(ip, port);
        // Default timeout: 600 seconds (10 minutes) for zone transfers, or use provided timeout
        // This is much longer than DnsClient.NET's default 5 seconds, which is too short for large zones
        _timeout = timeout ?? TimeSpan.FromSeconds(600);
    }

    public async Task<List<DnsResourceRecord>> FetchZoneAsync(string zoneName, CancellationToken cancellationToken = default)
    {
        // Ensure zone name has trailing dot
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";

        // Use DnsClient.NET's built-in AXFR support with TCP
        // Note: LookupClient doesn't implement IDisposable and is designed to be reused
        // Creating a new instance per call is acceptable for this use case
        var clientOptions = new LookupClientOptions(_endpoint)
        {
            UseTcpOnly = true, // AXFR requires TCP
            Timeout = _timeout // Configure timeout for zone transfers (default 600 seconds)
        };
        var client = new LookupClient(clientOptions);

        try
        {
            var result = await client.QueryAsync(normalizedZoneName, QueryType.AXFR, cancellationToken: cancellationToken);
            
            if (result.HasError)
            {
                throw new Exception($"AXFR query failed: {result.ErrorMessage}");
            }

            var records = result.Answers.ToList();
            
            // Validate that the transfer is complete
            // According to RFC 5936, AXFR should start and end with SOA records
            ValidateZoneTransferComplete(records, zoneName);
            
            return records;
        }
        catch (TaskCanceledException ex)
        {
            throw new Exception($"AXFR transfer for zone {zoneName} from upstream {_upstreamAddress} was cancelled or timed out: {ex.Message}", ex);
        }
        catch (System.Net.Sockets.SocketException ex)
        {
            throw new Exception($"AXFR transfer for zone {zoneName} from upstream {_upstreamAddress} failed due to network error: {ex.Message}", ex);
        }
        catch (System.IO.IOException ex)
        {
            throw new Exception($"AXFR transfer for zone {zoneName} from upstream {_upstreamAddress} failed due to I/O error (connection may have been aborted): {ex.Message}", ex);
        }
        catch (Exception ex)
        {
            // Check if it's already our custom exception (to avoid double-wrapping)
            if (ex.Message.Contains("incomplete") || ex.Message.Contains("missing SOA"))
            {
                throw;
            }
            throw new Exception($"Failed to fetch zone {zoneName} from upstream {_upstreamAddress}: {ex.Message}", ex);
        }
    }
    
    /// <summary>
    /// Validates that a zone transfer is complete by checking for SOA records at start and end.
    /// According to RFC 5936, AXFR transfers must start and end with the same SOA record.
    /// </summary>
    private void ValidateZoneTransferComplete(List<DnsResourceRecord> records, string zoneName)
    {
        if (records == null || records.Count == 0)
        {
            throw new Exception($"Zone transfer for {zoneName} returned no records - transfer may have been aborted");
        }
        
        // Find all SOA records
        var soaRecords = records.Where(r => r.RecordType == DnsClient.Protocol.ResourceRecordType.SOA)
            .Cast<DnsClient.Protocol.SoaRecord>()
            .ToList();
        
        // Must have at least 2 SOA records (start and end)
        if (soaRecords.Count < 2)
        {
            throw new Exception(
                $"Zone transfer for {zoneName} appears incomplete - expected 2 SOA records (start and end) but found {soaRecords.Count}. " +
                $"Total records received: {records.Count}. Transfer may have been aborted mid-way.");
        }
        
        // Check that first and last records are SOA
        var firstRecord = records[0];
        var lastRecord = records[records.Count - 1];
        
        if (firstRecord.RecordType != DnsClient.Protocol.ResourceRecordType.SOA)
        {
            throw new Exception(
                $"Zone transfer for {zoneName} appears incomplete - first record is not SOA (type: {firstRecord.RecordType}). " +
                $"Transfer may have been aborted or corrupted.");
        }
        
        if (lastRecord.RecordType != DnsClient.Protocol.ResourceRecordType.SOA)
        {
            throw new Exception(
                $"Zone transfer for {zoneName} appears incomplete - last record is not SOA (type: {lastRecord.RecordType}). " +
                $"Transfer may have been aborted mid-way. Total records received: {records.Count}");
        }
        
        // Verify that first and last SOA records match (same serial)
        var firstSoa = soaRecords[0];
        var lastSoa = soaRecords[soaRecords.Count - 1];
        
        if (firstSoa.Serial != lastSoa.Serial)
        {
            throw new Exception(
                $"Zone transfer for {zoneName} appears corrupted - first SOA serial ({firstSoa.Serial}) does not match last SOA serial ({lastSoa.Serial}). " +
                $"Transfer may have been aborted or mixed with another transfer.");
        }
        
        // Additional check: verify SOA records are at the expected positions
        if (records[0] != firstSoa || records[records.Count - 1] != lastSoa)
        {
            throw new Exception(
                $"Zone transfer for {zoneName} appears corrupted - SOA records are not at start and end positions. " +
                $"Transfer may have been aborted or corrupted.");
        }
    }

    public async Task<uint> GetSoaSerialAsync(string zoneName, CancellationToken cancellationToken = default)
    {
        // Note: LookupClient doesn't implement IDisposable and is designed to be reused
        // Creating a new instance per call is acceptable for this use case
        // Use shorter timeout for SOA queries (30 seconds should be sufficient)
        var clientOptions = new LookupClientOptions(_endpoint)
        {
            Timeout = TimeSpan.FromSeconds(30) // SOA queries are quick, 30 seconds is sufficient
        };
        var client = new LookupClient(clientOptions);
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";
        
        var queryResult = await client.QueryAsync(normalizedZoneName, QueryType.SOA, QueryClass.IN, cancellationToken: cancellationToken);
        
        if (queryResult.HasError)
        {
            throw new Exception($"Failed to query SOA: {queryResult.ErrorMessage}");
        }

        var soaRecord = queryResult.Answers.OfType<SoaRecord>().FirstOrDefault();
        if (soaRecord != null)
        {
            return (uint)soaRecord.Serial;
        }

        throw new Exception($"No SOA record found in zone {zoneName}");
    }

    public void Dispose()
    {
        // Nothing to dispose
    }
}
