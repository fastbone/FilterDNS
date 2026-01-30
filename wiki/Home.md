# FilterDNS Proxy

Welcome to the FilterDNS Proxy wiki!

FilterDNS Proxy is a .NET 10-based DNS master proxy server that serves zone transfers (AXFR/IXFR) to configured slave DNS servers, with IP whitelisting, NOTIFY support, and selective record filtering.

## Quick Links

- [[Installation]] - Get started with FilterDNS
- [[Configuration]] - Configure zones and settings
- [[Use-Cases]] - Common usage scenarios
- [[Architecture]] - How FilterDNS works
- [[Troubleshooting]] - Solve common issues
- [[FAQ]] - Frequently asked questions

## Key Features

- ✅ **Zone Transfer Support**: Full AXFR/IXFR support with zone history tracking
- ✅ **IP Whitelisting**: Enforce strict access control for zone transfers
- ✅ **NOTIFY Support**: RFC 1996-compliant NOTIFY messages
- ✅ **Record Filtering**: Filter/modify SOA, NS, and private IP records
- ✅ **Health Checks**: Monitor filtered zone data
- ✅ **Zone History**: Persistent zone version tracking for IXFR

## Quick Start

1. [[Installation|Install FilterDNS]]
2. [[Configuration|Configure your zones]]
3. Start the service: `sudo systemctl start filter-dns`
4. Verify: Check logs and test zone transfers

## Use Cases

FilterDNS is perfect for:
- Hiding Active Directory nameservers from public DNS
- Filtering private IP addresses from Internet zones
- Separating internal and external DNS views
- Controlling zone transfer access
- Customizing SOA records

See [[Use-Cases]] for detailed scenarios and examples.

## Compatibility

FilterDNS is compatible with:
- **Knot DNS** - Fully tested and supported
- **BIND** - Compatible with BIND master and slave servers
- **Other RFC-compliant DNS servers** - Should work with any server following RFC 1995 and RFC 1996

## Getting Help

- Check the [[Troubleshooting]] guide for common issues
- Review the [[FAQ]] for answers to common questions
- Open an issue on GitHub for bugs or feature requests

## License

FilterDNS is licensed under **GNU General Public License v3.0 (GPL-3.0)**.
