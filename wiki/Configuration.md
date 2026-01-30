# Configuration Guide

This guide covers all configuration options available in FilterDNS Proxy.

## Configuration File

FilterDNS uses a JSON configuration file (`appsettings.json`). Start by copying the example:

```bash
cp appsettings.example.json appsettings.json
```

## Server Configuration

The `Server` section contains global server settings:

```json
{
  "Server": {
    "ListenAddress": "0.0.0.0",
    "ListenPort": 53,
    "LogLevel": "Information",
    "UpstreamPollInterval": 300,
    "IxfrResponseMode": "Incremental",
    "DataDirectory": "./data",
    "DefaultIxfrHistoryDepth": 20,
    "ExportBindZoneFiles": true,
    "HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8"],
    "HistoryCleanup": {
      "Enabled": true,
      "IntervalSeconds": 3600,
      "RetentionDays": 7
    },
    "Seq": {
      "Enabled": false,
      "ServerUrl": "",
      "ApiKey": ""
    }
  }
}
```

### Server Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `ListenAddress` | string | `"0.0.0.0"` | IP address to listen on (0.0.0.0 = all interfaces) |
| `ListenPort` | int | `53` | Port to listen on (requires root privileges) |
| `LogLevel` | string | `"Information"` | Log level: Trace, Debug, Information, Warning, Error, Critical |
| `UpstreamPollInterval` | int | `300` | Seconds between upstream zone polls |
| `IxfrResponseMode` | string | `"Incremental"` | IXFR response mode: "Incremental" or "FullZone" |
| `DataDirectory` | string | `"./data"` | Directory for zone history and data files |
| `DefaultIxfrHistoryDepth` | int | `20` | Default number of zone versions to keep in history |
| `ExportBindZoneFiles` | bool | `true` | Export zone versions as BIND format files |
| `HealthCheckAcl` | array | `[]` | IP addresses/networks allowed for health check queries |
| `HistoryCleanup.Enabled` | bool | `true` | Enable automatic cleanup of old zone files |
| `HistoryCleanup.IntervalSeconds` | int | `3600` | Cleanup interval in seconds |
| `HistoryCleanup.RetentionDays` | int | `7` | Days to keep zone files before deletion |
| `Seq.Enabled` | bool | `false` | Enable remote logging to Seq |
| `Seq.ServerUrl` | string | `""` | Seq server URL |
| `Seq.ApiKey` | string | `""` | Seq API key |

### IXFR Response Mode

- **Incremental** (default): Sends RFC 1995-compliant incremental IXFR responses with only changes
- **FullZone**: Always sends full zone transfers (AXFR format) in response to IXFR requests

Use `FullZone` mode if you experience zone data corruption or missing records after IXFR transfers.

## Zone Configuration

Each zone in the `Zones` array defines how a zone is filtered and served:

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.0.2.1:53",
      "CacheEnabled": true,
      "PollInterval": 300,
      "Ns1": "ns1.proxy.example.com",
      "Ns2": "ns2.proxy.example.com",
      "Ns3": "ns3.proxy.example.com",
      "Ns4": "ns4.proxy.example.com",
      "SoaRname": "admin.proxy.example.com",
      "FilterPrivateIPs": false,
      "PrivateIPRanges": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
      ],
      "Slaves": [
        {
          "Ip": "192.0.2.10",
          "Port": 53
        }
      ],
      "XferWhitelist": [
        "192.0.2.20",
        "2001:db8::/64"
      ],
      "SlaveVerificationEnabled": true,
      "SlaveVerificationDelay": 2,
      "SlaveVerificationRecordCountTolerance": 5,
      "IxfrHistoryDepth": 50
    }
  ]
}
```

### Zone Configuration Options

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `Name` | string | Yes | Zone name (e.g., "example.com") |
| `Upstream` | string | Yes | Upstream master DNS server (IP:port) |
| `CacheEnabled` | bool | No | Enable zone caching (default: true) |
| `PollInterval` | int | No | Polling interval in seconds (default: 300) |
| `Ns1` | string | Yes | Primary nameserver (also used for SOA mname) |
| `Ns2` | string | Yes | Secondary nameserver |
| `Ns3` | string | No | Additional nameserver |
| `Ns4` | string | No | Additional nameserver |
| `SoaRname` | string | No | SOA responsible person email (default: preserve original) |
| `FilterPrivateIPs` | bool | No | Filter A/AAAA records with private IPs (default: false) |
| `PrivateIPRanges` | array | No | Custom private IP ranges (CIDR notation) |
| `Slaves` | array | No | Slave DNS servers to NOTIFY (auto-whitelisted) |
| `XferWhitelist` | array | No | Additional IPs/networks allowed for zone transfers |
| `SlaveVerificationEnabled` | bool | No | Enable slave verification after transfers (default: true) |
| `SlaveVerificationDelay` | int | No | Seconds to wait before verification (default: 2) |
| `SlaveVerificationRecordCountTolerance` | int | No | Tolerance for record count differences (default: 5) |
| `IxfrHistoryDepth` | int | No | Zone-specific history depth (overrides DefaultIxfrHistoryDepth) |

### Nameserver Configuration

- **Ns1** and **Ns2** are required
- **Ns3** and **Ns4** are optional
- All configured nameservers replace the original NS records from upstream
- Ns1 is also used as the SOA mname (primary nameserver)

### Private IP Filtering

When `FilterPrivateIPs` is enabled, FilterDNS removes A and AAAA records pointing to private IP addresses.

**Default private IP ranges** (if `PrivateIPRanges` is empty):
- IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`
- IPv6: `fc00::/7`, `fe80::/10`, `::1`

**Custom ranges**: Specify custom CIDR ranges in `PrivateIPRanges`:
```json
"PrivateIPRanges": [
  "10.0.0.0/8",
  "172.20.0.0/16",
  "192.168.100.0/24"
]
```

### Slave Configuration

Slave servers are automatically:
- Added to the XFER whitelist
- Sent NOTIFY messages when zones update

```json
"Slaves": [
  {
    "Ip": "192.0.2.10",
    "Port": 53
  },
  {
    "Ip": "2001:db8::1",
    "Port": 53
  }
]
```

### XFER Whitelist

Additional IPs/networks allowed for zone transfers (beyond automatic slave IPs):

```json
"XferWhitelist": [
  "192.0.2.20",
  "2001:db8::/64",
  "10.0.0.0/8"
]
```

Supports both IPv4 and IPv6 addresses/networks in CIDR notation.

### Health Check ACL

Configure IPs/networks allowed to query FilterDNS for health checks:

```json
"HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8", "192.168.1.100"]
```

Queries from these IPs receive filtered zone data responses.

## Configuration Examples

### Example 1: Basic Zone with NS Replacement

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.0.2.1:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "Slaves": [
        {"Ip": "192.0.2.10", "Port": 53}
      ]
    }
  ]
}
```

### Example 2: Filter Private IPs

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.0.2.1:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "FilterPrivateIPs": true,
      "Slaves": [
        {"Ip": "192.0.2.10", "Port": 53}
      ]
    }
  ]
}
```

### Example 3: Custom SOA and Multiple Slaves

```json
{
  "Zones": [
    {
      "Name": "example.com",
      "Upstream": "192.0.2.1:53",
      "Ns1": "ns1.publicdns.com",
      "Ns2": "ns2.publicdns.com",
      "Ns3": "ns3.publicdns.com",
      "SoaRname": "admin.publicdns.com",
      "FilterPrivateIPs": true,
      "Slaves": [
        {"Ip": "192.0.2.10", "Port": 53},
        {"Ip": "192.0.2.11", "Port": 53}
      ],
      "XferWhitelist": ["192.0.2.20"]
    }
  ]
}
```

## Configuration Validation

FilterDNS validates configuration on startup:
- Required fields must be present
- IP addresses must be valid
- Port numbers must be in valid range (1-65535)
- Zone names are normalized (trailing dots removed)
- Invalid slave entries are automatically filtered out

## Reloading Configuration

FilterDNS reads configuration on startup. To apply changes:

1. Edit `appsettings.json`
2. Restart the service:
   ```bash
   sudo systemctl restart filter-dns
   ```

## Next Steps

- [[Installation]] - Installation instructions
- [[Use-Cases]] - Common usage scenarios
- [[Troubleshooting]] - Solve configuration issues
