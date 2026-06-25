using System.Net;
using System.Net.Sockets;

namespace FilterDns.Net;

public sealed class CidrRange
{
    private readonly byte[] _networkBytes;
    private readonly int _fullBytes;
    private readonly int _remainingBits;

    public CidrRange(IPAddress networkAddress, int prefixLength)
    {
        var normalizedNetworkAddress = NormalizeAddress(networkAddress);
        ValidatePrefixLength(normalizedNetworkAddress, prefixLength);

        _networkBytes = normalizedNetworkAddress.GetAddressBytes();
        _fullBytes = prefixLength / 8;
        _remainingBits = prefixLength % 8;
    }

    public bool Contains(IPAddress address)
    {
        var normalizedAddress = NormalizeAddress(address);
        var addressBytes = normalizedAddress.GetAddressBytes();

        if (addressBytes.Length != _networkBytes.Length)
        {
            return false;
        }

        for (var i = 0; i < _fullBytes; i++)
        {
            if (addressBytes[i] != _networkBytes[i])
            {
                return false;
            }
        }

        if (_remainingBits == 0)
        {
            return true;
        }

        var mask = (byte)(0xFF << (8 - _remainingBits));
        return (addressBytes[_fullBytes] & mask) == (_networkBytes[_fullBytes] & mask);
    }

    private static IPAddress NormalizeAddress(IPAddress address)
    {
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    private static void ValidatePrefixLength(IPAddress address, int prefixLength)
    {
        var maxPrefixLength = address.AddressFamily switch
        {
            AddressFamily.InterNetwork => 32,
            AddressFamily.InterNetworkV6 => 128,
            _ => throw new ArgumentException($"Unsupported address family: {address.AddressFamily}", nameof(address))
        };

        if (prefixLength < 0 || prefixLength > maxPrefixLength)
        {
            throw new ArgumentOutOfRangeException(
                nameof(prefixLength),
                prefixLength,
                $"Prefix length must be between 0 and {maxPrefixLength} for {address.AddressFamily}");
        }
    }
}
