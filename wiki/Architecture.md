# Architecture & How It Works

This page explains the internal architecture and operation of FilterDNS Proxy.

## High-Level Architecture

```
┌─────────────────┐
│  Upstream Master │
│  (e.g., AD DNS)  │
└────────┬─────────┘
         │
         │ Polling / NOTIFY
         │
         ▼
┌─────────────────┐
│   FilterDNS     │
│     Proxy       │
│                 │
│  • Zone Fetch   │
│  • Filtering    │
│  • Caching      │
│  • History      │
└────────┬────────┘
         │
         │ NOTIFY / Zone Transfer
         │
         ▼
┌─────────────────┐
│  Slave Servers  │
│ (Public DNS)    │
└─────────────────┘
```

## Core Components

### 1. Upstream Polling & NOTIFY Reception

FilterDNS monitors upstream master DNS servers for zone changes:

- **Polling**: Periodically queries upstream for SOA records to detect serial number changes
- **NOTIFY Reception**: Receives and processes RFC 1996 NOTIFY messages from upstream masters
- **Change Detection**: Compares serial numbers to detect zone updates

### 2. Zone Fetching

When a change is detected:

1. FilterDNS performs a full zone transfer (AXFR) from the upstream master
2. Zone data is parsed and stored in memory
3. Serial number is extracted for change tracking

### 3. Zone Filtering

FilterDNS applies configured filters to the zone:

#### SOA Record Modification
- **mname** (Primary Nameserver): Replaced with configured `Ns1`
- **rname** (Responsible Person): Replaced with `SoaRname` if configured, otherwise preserved
- **Other SOA fields**: Serial number, TTL, refresh, retry, expire, minimum - all preserved

#### NS Record Replacement
- **All original NS records**: Removed
- **Configured NS records**: Added (Ns1, Ns2, Ns3, Ns4)
- Complete replacement ensures no internal nameservers leak through

#### Private IP Filtering
- **A records**: Removed if IP address matches private IP ranges
- **AAAA records**: Removed if IPv6 address matches private IP ranges
- **Configurable ranges**: Supports custom CIDR ranges via `PrivateIPRanges`

### 4. Zone Caching

Filtered zones are cached in memory for:
- Fast zone transfer responses
- Efficient serial number comparison
- Reduced upstream queries

### 5. Zone History Management

FilterDNS maintains zone version history for IXFR support:

- **History Storage**: Zone versions stored in JSON format (`{zonename}.json`)
- **Version Tracking**: Each zone version includes serial number and record set
- **History Depth**: Configurable per zone or globally
- **BIND Export**: Optional export of zone versions as BIND format files

### 6. NOTIFY Transmission

When a zone is updated, FilterDNS:

1. Sends RFC 1996-compliant NOTIFY messages to all configured slave servers
2. Uses proper DNS opcode (Opcode 4) with RD bit set to 0
3. Sends via UDP to each configured slave
4. Waits for acknowledgment (if slave responds)

### 7. Zone Transfer Handling

When a slave requests a zone transfer:

1. **IP Validation**: Client IP checked against whitelist (slaves + XferWhitelist)
2. **SOA Query Handling**: Handles SOA queries on TCP (some DNS servers send these before transfers)
3. **Transfer Type**: Determines if client requests AXFR or IXFR
4. **IXFR Processing**: 
   - Calculates differences between client serial and server serial
   - Sends incremental changes (if history available and mode is "Incremental")
   - Falls back to AXFR if history unavailable or mode is "FullZone"
5. **Streaming**: Streams zone data with proper connection lifecycle management
6. **Authorization**: Refuses unauthorized transfer requests

## Data Flow

### Zone Update Flow

```
1. Upstream Master changes zone (serial number increases)
   ↓
2. FilterDNS detects change (polling or NOTIFY)
   ↓
3. FilterDNS fetches zone from upstream (AXFR)
   ↓
4. FilterDNS applies filters:
   - Replace NS records
   - Modify SOA mname/rname
   - Filter private IPs (if enabled)
   ↓
5. FilterDNS caches filtered zone
   ↓
6. FilterDNS saves zone version to history
   ↓
7. FilterDNS sends NOTIFY to all configured slaves
   ↓
8. Slaves request zone transfer (AXFR/IXFR)
   ↓
9. FilterDNS serves filtered zone to authorized slaves
```

### Zone Transfer Flow (IXFR)

```
1. Slave sends IXFR request with client serial
   ↓
2. FilterDNS validates client IP against whitelist
   ↓
3. FilterDNS checks zone history for client serial
   ↓
4. If history available:
   - Calculate differences between client serial and server serial
   - Send incremental changes (deletions + additions)
   ↓
5. If history unavailable or mode is "FullZone":
   - Send full zone transfer (AXFR format)
   ↓
6. Slave applies changes and updates zone
```

## Storage Structure

```
data/
├── history/
│   ├── example.com.json          # Zone history database (JSON)
│   ├── anotherdomain.com.json
│   └── zones/                     # BIND format exports (optional)
│       ├── example.com_2026012017.zone
│       └── example.com_2026012018.zone
```

### Zone History Format

Zone history is stored as JSON:

```json
{
  "versions": [
    {
      "serial": 2026012017,
      "records": [...],
      "timestamp": "2026-01-20T17:00:00Z"
    },
    {
      "serial": 2026012018,
      "records": [...],
      "timestamp": "2026-01-20T18:00:00Z"
    }
  ]
}
```

## Network Protocols

### DNS Protocol Support

- **UDP**: NOTIFY messages, health check queries
- **TCP**: Zone transfers (AXFR/IXFR), SOA queries
- **RFC 1995**: Incremental Zone Transfer (IXFR)
- **RFC 1996**: DNS NOTIFY

### Connection Handling

- **Multiple queries per TCP connection**: Supports SOA queries followed by zone transfers
- **Connection lifecycle**: Proper connection management for reliable transfers
- **Timeout handling**: Graceful handling of connection timeouts

## Security Features

### IP Whitelisting

- **Automatic slave whitelisting**: Configured slaves automatically added to whitelist
- **Explicit whitelist**: Additional IPs/networks via `XferWhitelist`
- **Health check ACL**: Separate ACL for health check queries
- **NOTIFY validation**: Only accepts NOTIFY from configured upstream masters

### Access Control

- **Zone transfer authorization**: Only whitelisted IPs can transfer zones
- **Health check authorization**: Only ACL IPs can query for health checks
- **NOTIFY validation**: Validates NOTIFY source IP

## Performance Considerations

### Caching

- Filtered zones cached in memory for fast responses
- Reduces filtering overhead on each transfer request
- Cache updated only when upstream zone changes

### History Management

- Configurable history depth per zone
- Automatic cleanup of old zone files
- Efficient diff calculation for IXFR

### Polling vs NOTIFY

- **Polling**: Configurable interval (default: 300 seconds)
- **NOTIFY**: Immediate update when upstream sends NOTIFY
- **Hybrid**: Both methods work together

## Error Handling

### Upstream Failures

- Logs errors when upstream is unreachable
- Continues serving cached zones
- Retries on next poll interval

### Transfer Failures

- Logs transfer errors
- Refuses unauthorized transfers
- Handles connection resets gracefully

### History Issues

- Falls back to AXFR if history unavailable
- Logs warnings for suspicious IXFR responses
- Validates zone data integrity

## Next Steps

- [[Configuration]] - Configure FilterDNS
- [[Use-Cases]] - Common usage scenarios
- [[Troubleshooting]] - Solve common issues
