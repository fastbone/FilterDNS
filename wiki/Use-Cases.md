# Use Cases & Scenarios

FilterDNS Proxy is designed to solve common DNS infrastructure challenges. This page details real-world scenarios where FilterDNS provides value.

## 🔒 Hide Active Directory Nameservers from Public DNS

### Problem

Your Active Directory DNS servers expose internal nameserver records (e.g., `dc1.ad.company.local`, `dc2.ad.company.local`) in public DNS zones. This reveals internal infrastructure details and can be a security concern.

### Solution

FilterDNS replaces all NS records with your configured public nameservers before serving zones to public slave servers.

### Configuration Example

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "Ns3": "ns3.publicdns.com",
      "Ns4": "ns4.publicdns.com",
      "SoaRname": "admin.publicdns.com",
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53}
      ]
    }
  ]
}
```

### Result

- **Upstream zone** shows: `ns1.ad.company.local`, `ns2.ad.company.local`
- **Public zone** shows: `ns1.publicdns.com`, `ns2.publicdns.com`, `ns3.publicdns.com`, `ns4.publicdns.com`
- Internal AD infrastructure remains hidden

## 🌐 Filter Private IP Addresses from Internet Zones

### Problem

Your internal DNS zones contain A and AAAA records pointing to private IP addresses (RFC 1918). These records should not appear in public DNS zones served to the Internet.

### Solution

Enable `FilterPrivateIPs` to automatically remove all A and AAAA records pointing to private IP addresses.

### Configuration Example

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "FilterPrivateIPs": true,
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53}
      ]
    }
  ]
}
```

### What Gets Filtered

- **IPv4 Private Ranges**: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
- **IPv6 Private Ranges**: fc00::/7, fe80::/10, ::1

### Custom Private IP Ranges

You can define custom private IP ranges:

```json
{
  "FilterPrivateIPs": true,
  "PrivateIPRanges": [
    "10.0.0.0/8",
    "172.20.0.0/16",
    "192.168.100.0/24"
  ]
}
```

### Result

- **Upstream zone** contains: `www.example.com A 192.168.1.100`
- **Public zone** contains: (record removed - no A record for www.example.com)
- Only public IP addresses are served to slave servers

## 🏢 Separate Internal and External DNS Views

### Problem

You need to maintain separate DNS views: one for internal use (with private IPs and internal services) and one for public use (only public IPs and public services).

### Solution

Use FilterDNS as a bridge between your internal DNS infrastructure and public-facing DNS infrastructure.

### Architecture

```
Internal DNS (AD)
    ↓
FilterDNS (filters zones)
    ↓
Public Slave DNS Servers
    ↓
Internet
```

### Configuration Example

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "FilterPrivateIPs": true,
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53},
        {"Ip": "203.0.113.11", "Port": 53}
      ]
    }
  ]
}
```

### Result

- **Internal DNS** contains all records (public + private)
- **Public DNS** contains only public-facing records
- Changes in internal DNS automatically propagate to public DNS (via polling or NOTIFY)

## 🔐 Control Zone Transfer Access

### Problem

You need strict control over which servers can perform zone transfers (AXFR/IXFR) from your DNS master.

### Solution

FilterDNS enforces IP whitelisting for zone transfers. Configured slaves are automatically whitelisted, and you can add additional authorized IPs.

### Configuration Example

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53},
        {"Ip": "203.0.113.11", "Port": 53}
      ],
      "XferWhitelist": [
        "203.0.113.20",
        "2001:db8::/64"
      ]
    }
  ]
}
```

### Result

- **Authorized IPs** (slaves + whitelist) can perform zone transfers
- **Unauthorized IPs** receive REFUSED response
- Automatic NOTIFY messages sent to configured slaves

## 🎯 Customize SOA Records

### Problem

Your upstream master DNS has SOA records pointing to internal infrastructure (e.g., `dc1.internal.company.local`). You want public DNS zones to show public nameservers in SOA records.

### Solution

FilterDNS modifies SOA records to use your configured nameservers while preserving serial numbers and other critical fields.

### Configuration Example

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "SoaRname": "admin.publicdns.com",
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53}
      ]
    }
  ]
}
```

### Result

- **Upstream SOA**: `example.com SOA dc1.internal.company.local admin.internal.company.local 2026012017 ...`
- **Public SOA**: `example.com SOA ns1.publicdns.com admin.publicdns.com 2026012017 ...`
- Serial number and other SOA fields preserved

## 📊 Health Check Integration

### Problem

You need to monitor that your filtered zones are being served correctly and verify that filtering rules are working as expected.

### Solution

Use FilterDNS health check feature to query filtered zone data from monitoring systems.

### Configuration Example

```json
{
  "Server": {
    "HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8", "192.168.1.100"]
  },
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com"
    }
  ]
}
```

### Testing

From a whitelisted IP:

```bash
# Query for A record
dig @filterdns-server www.example.com A

# Query for NS records
dig @filterdns-server example.com NS

# Query for SOA record
dig @filterdns-server example.com SOA
```

### Result

- Monitoring systems can verify filtered zone data
- Same data that slave servers receive via AXFR
- Unauthorized IPs are ignored (existing behavior)

## 🔄 Hybrid DNS Architecture

### Problem

You have Active Directory as your authoritative DNS source, but you need to serve sanitized zones to public-facing DNS infrastructure.

### Solution

Use FilterDNS as a secure bridge between internal and external DNS infrastructure.

### Architecture Flow

1. **Active Directory** (upstream master) contains full zone data
2. **FilterDNS** polls or receives NOTIFY from AD
3. **FilterDNS** filters the zone (removes private IPs, replaces NS records)
4. **FilterDNS** sends NOTIFY to public slave servers
5. **Public Slave Servers** perform zone transfers and serve to Internet

### Configuration Example

```json
{
  "Server": {
    "UpstreamPollInterval": 300
  },
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "CacheEnabled": true,
      "PollInterval": 300,
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "FilterPrivateIPs": true,
      "Slaves": [
        {"Ip": "203.0.113.10", "Port": 53},
        {"Ip": "203.0.113.11", "Port": 53}
      ]
    }
  ]
}
```

### Result

- Internal changes automatically propagate to public DNS
- Private infrastructure remains hidden
- Public DNS shows only authorized nameservers and public IPs

## Additional Scenarios

### Scenario: Multiple Upstream Masters

FilterDNS can handle multiple zones from different upstream masters:

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.168.1.10:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com"
    },
    {
      "Name": "anotherdomain.com",
      "Upstream": "192.168.1.20:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com"
    }
  ]
}
```

### Scenario: IPv6 Support

FilterDNS fully supports IPv6:

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "[2001:db8::1]:53",
      "Slaves": [
        {"Ip": "2001:db8::10", "Port": 53}
      ],
      "XferWhitelist": [
        "2001:db8::/64"
      ]
    }
  ]
}
```

## Next Steps

- [[Configuration]] - Learn how to configure FilterDNS
- [[Architecture]] - Understand how FilterDNS works
- [[Troubleshooting]] - Solve common issues
