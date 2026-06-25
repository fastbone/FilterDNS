using System.Net;
using System.Net.Sockets;
using FilterDns.Net;

namespace FilterDns.Whitelist;

public class IpWhitelist
{
    private readonly List<IPNetwork> _networks = new();

    public IpWhitelist(IEnumerable<string> entries)
    {
        foreach (var entry in entries)
        {
            if (IPAddress.TryParse(entry, out var ip))
            {
                // Single IP address - add as /32 for IPv4 or /128 for IPv6
                var prefixLength = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
                _networks.Add(new IPNetwork(ip, prefixLength));
            }
            else if (entry.Contains('/'))
            {
                // CIDR notation
                var parts = entry.Split('/');
                if (parts.Length == 2 && IPAddress.TryParse(parts[0], out var networkIp) && int.TryParse(parts[1], out var prefixLength))
                {
                    _networks.Add(new IPNetwork(networkIp, prefixLength));
                }
                else
                {
                    throw new ArgumentException($"Invalid CIDR notation: {entry}");
                }
            }
            else
            {
                throw new ArgumentException($"Invalid IP/network entry: {entry}");
            }
        }
    }

    public bool Allows(IPAddress ip)
    {
        return _networks.Any(network => network.Contains(ip));
    }

    private class IPNetwork
    {
        private readonly CidrRange _range;

        public IPNetwork(IPAddress address, int prefixLength)
        {
            _range = new CidrRange(address, prefixLength);
        }

        public bool Contains(IPAddress address)
        {
            return _range.Contains(address);
        }
    }
}



