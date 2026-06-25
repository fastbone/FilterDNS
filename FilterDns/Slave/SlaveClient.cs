using System.Net;
using DnsClient;
using DnsClient.Protocol;

namespace FilterDns.Slave;

public class SlaveClient : IDisposable
{
    /// <summary>
    /// Queries the SOA record from a slave server for the specified zone.
    /// </summary>
    /// <param name="zoneName">The zone name to query</param>
    /// <param name="slaveEndpoint">The IP endpoint of the slave server</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The SOA serial number</returns>
    public static async Task<uint> QuerySoaAsync(string zoneName, IPEndPoint slaveEndpoint, CancellationToken cancellationToken = default)
    {
        var client = new LookupClient(slaveEndpoint);
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";
        
        var queryResult = await client.QueryAsync(normalizedZoneName, QueryType.SOA, QueryClass.IN, cancellationToken: cancellationToken);
        
        if (queryResult.HasError)
        {
            throw new Exception($"Failed to query SOA from slave {slaveEndpoint}: {queryResult.ErrorMessage}");
        }

        var soaRecord = queryResult.Answers.OfType<SoaRecord>().FirstOrDefault();
        if (soaRecord != null)
        {
            return (uint)soaRecord.Serial;
        }

        throw new Exception($"No SOA record found in zone {zoneName} from slave {slaveEndpoint}");
    }

    /// <summary>
    /// Initiates an AXFR zone transfer from a slave server to our daemon.
    /// The slave server will connect to our XferHandler to perform the transfer.
    /// </summary>
    /// <param name="zoneName">The zone name to transfer</param>
    /// <param name="slaveEndpoint">The IP endpoint of the slave server</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>List of DNS resource records from the zone transfer</returns>
    public static async Task<List<DnsResourceRecord>> FetchZoneFromSlaveAsync(string zoneName, IPEndPoint slaveEndpoint, CancellationToken cancellationToken = default)
    {
        // Ensure zone name has trailing dot
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";

        // Use DnsClient.NET's built-in AXFR support with TCP
        var clientOptions = new LookupClientOptions(slaveEndpoint)
        {
            UseTcpOnly = true // AXFR requires TCP
        };
        var client = new LookupClient(clientOptions);

        try
        {
            var result = await client.QueryAsync(normalizedZoneName, QueryType.AXFR, cancellationToken: cancellationToken);
            
            if (result.HasError)
            {
                throw new Exception($"AXFR query failed from slave {slaveEndpoint}: {result.ErrorMessage}");
            }

            // Return all records from the AXFR response
            // DnsClient.NET handles all the parsing automatically
            return result.Answers.ToList();
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to fetch zone {zoneName} from slave {slaveEndpoint}: {ex.Message}", ex);
        }
    }

    public void Dispose()
    {
        // Nothing to dispose - static methods don't require instance disposal
    }
}
