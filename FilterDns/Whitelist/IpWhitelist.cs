using System.Net;
using System.Net.Sockets;

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
        private readonly IPAddress _networkAddress;
        private readonly int _prefixLength;
        private readonly byte[] _networkBytes;
        private readonly int _byteLength;

        public IPNetwork(IPAddress address, int prefixLength)
        {
            _networkAddress = address;
            _prefixLength = prefixLength;
            _networkBytes = address.GetAddressBytes();
            _byteLength = (prefixLength + 7) / 8; // Number of bytes to compare
        }

        public bool Contains(IPAddress address)
        {
            var addressBytes = address.GetAddressBytes();
            if (addressBytes.Length != _networkBytes.Length)
                return false;

            for (int i = 0; i < _byteLength; i++)
            {
                if (addressBytes[i] != _networkBytes[i])
                    return false;
            }

            // Check remaining bits if prefix length is not byte-aligned
            if (_prefixLength % 8 != 0)
            {
                var bitsInLastByte = _prefixLength % 8;
                var mask = (byte)(0xFF << (8 - bitsInLastByte));
                if ((addressBytes[_byteLength] & mask) != (_networkBytes[_byteLength] & mask))
                    return false;
            }

            return true;
        }
    }
}



