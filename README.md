# Filter DNS Proxy

A .NET 10-based DNS master proxy server that serves zone transfers (AXFR/IXFR) to configured slave DNS servers, with IP whitelisting, NOTIFY support, and selective record filtering.

## Use Cases & Scenarios

FilterDNS Proxy enables you to sanitize and transform DNS zones before serving them to public-facing slave DNS servers. Here are some common scenarios where FilterDNS proves invaluable:

### 🔒 Hide Internal Infrastructure from Public DNS

**Hide Active Directory Nameservers from Public**: Protect your internal infrastructure by replacing internal nameserver records (e.g., `dc1.internal.company.com`, `dc2.internal.company.com`) with public-facing nameservers. Your internal AD DNS servers remain hidden while your public DNS zones show only authorized nameservers.

**Example**: Your upstream master DNS (e.g., Active Directory) exposes internal nameservers like `ns1.ad.company.local` and `ns2.ad.company.local`. FilterDNS replaces these with your configured public nameservers (e.g., `ns1.publicdns.com`, `ns2.publicdns.com`) before serving zones to public slave servers.

### 🌐 Ensure No Private IPs in Internet Zones

**Filter Private IP Addresses**: Prevent private/internal IP addresses from leaking into public DNS zones. Enable `FilterPrivateIPs` to automatically remove A and AAAA records pointing to RFC 1918 addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and other private ranges.

**Example**: Your internal DNS zone contains records like `www.example.com A 192.168.1.100` or `api.example.com AAAA fc00::1`. FilterDNS removes these private IP records, ensuring only public IP addresses are served to your public slave DNS servers.

### 🏢 Separate Internal and External DNS Views

**Maintain Different DNS Views**: Keep your internal DNS infrastructure separate from your public-facing DNS. Your internal master DNS can contain internal records, private IPs, and internal nameservers, while FilterDNS serves a sanitized version to public slaves.

**Example**: Internal DNS contains both public services (`www.example.com`) and internal services (`internal.example.com` pointing to private IPs). FilterDNS filters out internal services and private IPs, serving only public-facing records to external slave servers.

### 🔐 Control Zone Transfer Access

**Enforce Strict Access Control**: Use IP whitelisting to ensure only authorized slave DNS servers can perform zone transfers. Automatically whitelist configured slaves while maintaining additional control through explicit whitelist entries.

**Example**: Configure your public slave DNS servers (e.g., Knot DNS, BIND) in the `Slaves` array. FilterDNS automatically adds them to the transfer whitelist and sends NOTIFY messages when zone updates are available, while blocking unauthorized transfer attempts.

### 🎯 Customize SOA Records

**Modify SOA Metadata**: Update SOA (Start of Authority) records to reflect your public DNS infrastructure. Change the primary nameserver (mname) and responsible person (rname) email address while preserving serial numbers and other critical SOA fields.

**Example**: Your upstream master has `example.com SOA dc1.internal.company.local admin.internal.company.local ...`. FilterDNS transforms this to `example.com SOA ns1.publicdns.com admin.publicdns.com ...` while maintaining the original serial number for proper zone synchronization.

### 📊 Health Check Integration

**Monitor Filtered Zone Data**: Use the health check feature to verify that your filtered zones are being served correctly. Configure monitoring systems to query FilterDNS and receive filtered zone data responses, ensuring your filtering rules are working as expected.

**Example**: Configure your monitoring system's IP in `HealthCheckAcl` and query for records in your zones. FilterDNS responds with the same filtered data that slave servers receive, allowing you to verify filtering is working correctly.

### 🔄 Hybrid DNS Architecture

**Bridge Internal and External DNS**: Use FilterDNS as a secure bridge between your internal DNS infrastructure (e.g., Active Directory) and external/public DNS infrastructure. Internal changes are automatically detected, filtered, and propagated to public slaves.

**Example**: Your Active Directory DNS server is the authoritative source for `example.com`. FilterDNS polls or receives NOTIFY from AD, filters the zone (removes private IPs, replaces NS records), and serves the sanitized zone to public slave DNS servers with automatic NOTIFY support.

## Features

- **Zone Transfer Support**: Serves AXFR/IXFR transfers to authorized slave servers
  - **Full IXFR Support**: RFC 1995-compliant Incremental Zone Transfer (IXFR) with zone history tracking
  - **Zone History**: Maintains version history for efficient incremental transfers
  - **Persistent History**: Zone history persists across restarts
  - **BIND Zone Export**: Optional export of zone versions as human-readable BIND format files
  - **Configurable Response Mode**: Choose between incremental IXFR responses or full zone transfers (AXFR format) for IXFR requests
  - **Validation Logging**: Automatic detection and warnings for suspicious IXFR responses that might indicate data corruption
- **IP Whitelisting**: Enforces XFER whitelists - only allows transfers from authorized IPs
- **Automatic Slave Whitelisting**: Configured slave servers are automatically added to the XFER whitelist
- **NOTIFY Support**: 
  - Sends RFC 1996-compliant NOTIFY messages to slave servers when filtered zone updates are available
  - Receives and processes NOTIFY messages from upstream master servers
  - Automatically triggers zone updates and slave notifications when upstream masters send NOTIFY
- **TCP Connection Handling**: 
  - Supports multiple queries per TCP connection (e.g., SOA queries followed by zone transfers)
  - Handles SOA queries on TCP that some DNS servers (like Knot DNS) send before zone transfers
  - Graceful connection lifecycle management for reliable zone transfers
- **Health Check Support**: Responds to DNS queries from configured IP addresses/blocks with filtered zone data for service health verification
- **Record Filtering**:
  - **SOA**: Modifies Primary Server (mname) and optionally Responsible Person (rname)
  - **NS**: Completely replaces all NS records with configured ones
  - **Private IP Filtering**: Optionally filters out A and AAAA records pointing to private IP addresses (configurable per zone)
  - Preserves serial numbers, TTLs, and other SOA fields
- **Zone Export**: Export filtered zones to BIND DNS format for debugging and verification
- **Zone History Management**: 
  - Automatic zone version tracking for IXFR support
  - Configurable history retention per zone
  - Optional BIND format zone file export for human reference
  - Automatic cleanup of old zone files based on retention policy
- **Rapid Update Handling**: Robust handling of multiple quick zone updates on master servers
  - **NOTIFY Debouncing**: Coalesces rapid NOTIFYs from upstream to prevent update cascades
  - **Slave NOTIFY Rate Limiting**: Prevents flooding slaves during rapid updates
  - **Dynamic History Depth**: Automatically increases IXFR history depth during busy periods
  - **Version Locking**: Ensures consistent zone snapshots during transfers
  - **IXFR Chain Validation**: Validates complete diff chains before serving IXFR to prevent corrupt transfers

## Requirements

- .NET 10 SDK
- Linux AMD64 (for native builds)

## Configuration

Copy `appsettings.example.json` to `appsettings.json` and configure your zones:

```json
{
  "Server": {
    "ListenAddress": "0.0.0.0",
    "ListenPort": 53,
    "LogLevel": "Information",
    "UpstreamPollInterval": 300,
    "IxfrResponseMode": "Incremental",
    "HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8"],
    "Seq": {
      "Enabled": false,
      "ServerUrl": "",
      "ApiKey": ""
    }
  },
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
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1"
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

### Configuration Notes

#### Server Configuration

- **DataDirectory** (optional, default: `"./data"`): Directory where zone history files are stored. History files are stored in `{DataDirectory}/history/` subdirectory.
- **DefaultIxfrHistoryDepth** (optional, default: `20`): Default number of zone versions to keep in history for IXFR support. Can be overridden per zone with `IxfrHistoryDepth`.
- **ExportBindZoneFiles** (optional, default: `true`): Whether to export zone versions as BIND format files (`{zonename}_{serial}.zone`) for human reference. Files are stored in `{DataDirectory}/history/zones/`.
- **IxfrResponseMode** (optional, default: `"Incremental"`): Controls how IXFR requests are handled.
  - `"Incremental"`: Send RFC 1995-compliant incremental IXFR responses with only the changes between versions (default, recommended)
  - `"FullZone"`: Always send full zone transfers (AXFR format) in response to IXFR requests. Use this mode if you experience issues with incremental transfers or zone data corruption.
  - **When to use FullZone mode**: If you notice zones losing records after IXFR transfers (e.g., zone size dropping unexpectedly), switching to `FullZone` mode ensures complete zone data is always transferred. This is less efficient but more reliable.
- **HistoryCleanup** (optional): Configuration for automatic cleanup of old zone files.
  - **Enabled** (optional, default: `true`): Enable automatic cleanup of old zone files.
  - **IntervalSeconds** (optional, default: `3600`): How often to run cleanup (in seconds). Default is 1 hour.
  - **RetentionDays** (optional, default: `7`): How many days to keep zone files before deletion. Files older than this will be automatically deleted.

#### Rapid Update Handling Configuration

These settings help maintain slave synchronization when your master DNS server experiences many quick zone updates in succession:

- **NotifyDebounceMs** (optional, default: `500`): Debounce time in milliseconds for NOTIFY processing. When multiple NOTIFYs arrive from the upstream master rapidly, FilterDNS waits this long for a quiet period before processing. This coalesces rapid updates and prevents cascade of zone fetches. Set to `0` to disable debouncing.
- **MinSlaveNotifyIntervalMs** (optional, default: `2000`): Minimum interval in milliseconds between sending NOTIFYs to slaves. Prevents flooding slaves with too many NOTIFYs during rapid updates. Set to `0` to disable.
- **EnableDynamicHistoryDepth** (optional, default: `true`): Automatically increases IXFR history depth during rapid update periods. When enabled, history depth expands based on update frequency, preventing version pruning before slaves can request intermediate versions.

#### Zone Configuration

- **HealthCheckAcl** (optional): List of IP addresses or CIDR blocks allowed to query the DNS server for health checks. Queries from these IPs will receive filtered zone data responses. Supports both IPv4 and IPv6 addresses/networks (e.g., `["127.0.0.1", "10.0.0.0/8", "2001:db8::/64"]`)
- **NS1** (required): Master NS server, also used for SOA mname
- **NS2** (required): Secondary NS server
- **NS3/NS4** (optional): Additional NS servers
- **SoaRname** (optional): If not provided, the original rname from upstream is preserved
- **FilterPrivateIPs** (optional, default: false): When enabled, filters out A and AAAA records that point to private IP addresses. This ensures zones served to slaves contain only public IP addresses.
- **PrivateIPRanges** (optional, default: empty): Custom list of IP ranges (CIDR notation) to consider as private. If empty or not specified, uses default RFC 1918 ranges:
  - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8 (loopback), 169.254.0.0/16 (link-local)
  - IPv6: fc00::/7 (unique local), fe80::/10 (link-local), ::1 (loopback)
  - Examples: `["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]` or `["10.0.0.0/8", "172.20.0.0/16"]` for custom ranges
- **Slaves**: IP addresses of slave servers to NOTIFY when zone updates occur. **These are automatically added to the XFER whitelist**
  - Each slave entry must have a valid IP address and port (default: 53)
  - Invalid slave configurations are automatically filtered out
  - NOTIFY messages are sent to all configured slaves whenever a zone is updated
- **XferWhitelist**: Additional IP addresses/networks allowed for zone transfers (beyond automatic slave IPs)
  - Useful for allowing zone transfers from monitoring tools or other authorized systems
  - Supports both IPv4 and IPv6 addresses/networks in CIDR notation
- **IxfrHistoryDepth** (optional): Per-zone override for IXFR history retention. If not specified, uses `DefaultIxfrHistoryDepth` from server configuration.
  - Determines how many zone versions to keep in history for this specific zone
  - Useful for zones with frequent updates that need more history, or zones with infrequent updates that need less
- **NotifyDebounceMs** (optional): Per-zone override for NOTIFY debounce time. Useful for zones with different update patterns. Set to `0` to disable debouncing for this zone. If not specified, uses `Server.NotifyDebounceMs`.
- **MinSlaveNotifyIntervalMs** (optional): Per-zone override for minimum NOTIFY interval to slaves. Useful for zones that can tolerate different notification rates. Set to `0` to disable for this zone. If not specified, uses `Server.MinSlaveNotifyIntervalMs`.

## Building

```bash
./build.sh
```

This will build the project for Linux AMD64 and output to `build/linux-x64/`.

## Deployment

```bash
./deploy.sh
```

This creates a timestamped `tar.gz` package in the `deploy/` directory with all necessary files to run on another machine.

## Running

### As a Service

1. Copy the deployment package to your target machine
2. Extract: `tar -xzf filter-dns-YYYYMMDD_HHMMSS.tar.gz`
3. Configure `appsettings.json`
4. Install the systemd service:
   ```bash
   sudo cp filter-dns.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable filter-dns
   sudo systemctl start filter-dns
   ```

### Manual Execution

1. Copy the deployment package to your target machine
2. Extract: `tar -xzf filter-dns-YYYYMMDD_HHMMSS.tar.gz`
3. Configure `appsettings.json`
4. Run: `./FilterDns`

## Zone Export

### Manual Export Command

You can export filtered zones to BIND DNS format for debugging and verification:

```bash
# Export to stdout
./FilterDns export example.com

# Export to file
./FilterDns export example.com /path/to/output.zone

# Alternative syntax
./FilterDns --export example.com
```

The export command:
- Fetches the zone from the configured upstream server
- Applies all configured filters (SOA mname/rname, NS replacement)
- Outputs the filtered zone in BIND DNS format

### Automatic Zone History Export

When `ExportBindZoneFiles` is enabled (default: `true`), FilterDNS automatically exports each zone version as a BIND format file:

- **Location**: `{DataDirectory}/history/zones/`
- **Naming**: `{zonename}_{serial}.zone`
- **Example**: `flm9_net_2026012017.zone`

These files provide human-readable snapshots of each zone version for debugging and reference. They are automatically cleaned up based on the `HistoryCleanup` retention policy.

### Zone History Files

Zone history is stored in two formats:

1. **JSON Database** (`{DataDirectory}/history/{zonename}.json`):
   - Machine-readable format for IXFR support
   - Contains all zone versions with metadata
   - Used internally for incremental transfers

2. **BIND Zone Files** (`{DataDirectory}/history/zones/{zonename}_{serial}.zone`):
   - Human-readable BIND format
   - Optional (controlled by `ExportBindZoneFiles`)
   - Useful for manual inspection and debugging

## How It Works

1. **Upstream Polling**: The proxy periodically polls upstream master DNS servers for zone changes
2. **NOTIFY Reception**: When an upstream master sends a NOTIFY message (RFC 1996), the proxy:
   - Validates the NOTIFY is from the configured upstream master IP
   - Immediately checks for zone updates (serial number comparison)
   - Fetches and filters the zone if serial has changed
   - Sends NOTIFY messages to all configured slave servers
3. **Change Detection**: When a serial number change is detected (via polling or NOTIFY), the zone is fetched
4. **Filtering**: SOA and NS records are modified according to configuration. If `FilterPrivateIPs` is enabled, A and AAAA records with private IP addresses are removed.
5. **Caching**: Filtered zones are cached for faster XFER responses
6. **NOTIFY Transmission**: When a zone is updated, RFC 1996-compliant NOTIFY messages are automatically sent to all configured slave servers:
   - NOTIFY messages use proper DNS opcode (Opcode 4) with RD bit set to 0 per RFC 1996
   - Sent via UDP to each configured slave server
   - Waits for acknowledgment from slave servers
7. **Zone Transfers**: When a slave requests a zone transfer:
   - Client IP is checked against the whitelist (slaves + additional entries)
   - SOA queries on TCP are handled (some DNS servers like Knot DNS send SOA queries before transfers)
   - Multiple queries per TCP connection are supported
   - If authorized, the filtered zone is streamed with proper connection lifecycle management
   - If not authorized, the request is refused
8. **Health Checks**: When a DNS query is received from an IP in the HealthCheckAcl:
   - The queried domain is looked up in configured zones
   - If found, filtered zone data matching the query type (A, AAAA, NS, SOA, etc.) is returned
   - If not found, NXDOMAIN is returned
   - This allows health check systems to verify the service is operational

## Health Checks

The health check feature allows monitoring systems to verify the DNS proxy service is working correctly by querying for records in configured zones.

### How to Use

1. Configure `HealthCheckAcl` in `appsettings.json` with the IP addresses or networks of your monitoring systems:
   ```json
   "HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8", "192.168.1.100"]
   ```

2. Query the DNS server from a whitelisted IP:
   ```bash
   # Query for an A record
   dig @localhost www.example.com A
   
   # Query for an AAAA record
   dig @localhost www.example.com AAAA
   
   # Query for NS records
   dig @localhost example.com NS
   
   # Query for SOA record
   dig @localhost example.com SOA
   ```

3. The server will respond with filtered zone data (same data that slaves receive via AXFR)

### Behavior

- **Authorized IPs**: Queries from IPs in `HealthCheckAcl` receive filtered zone data responses
- **Unauthorized IPs**: Queries from non-whitelisted IPs are ignored (existing behavior for regular queries)
- **NOTIFY Messages**: NOTIFY messages continue to work regardless of source IP
- **Zone Transfers**: Zone transfer requests continue to work as before (separate from health checks)
- **Query Types Supported**: A, AAAA, NS, SOA, and other standard DNS record types
- **Response Codes**: 
  - `NOERROR`: Query successful, records returned (or empty answer if no matching records)
  - `NXDOMAIN`: Queried domain not found in any configured zone
  - `SERVFAIL`: Error occurred (e.g., upstream fetch failure)

## DNS Server Compatibility

FilterDNS is compatible with standard DNS servers that support:
- **RFC 1996 NOTIFY**: Properly formatted NOTIFY messages with Opcode 4 and RD bit set to 0
- **RFC 1995 Zone Transfers**: Standard AXFR and IXFR zone transfer protocols
  - **Full IXFR Support**: Complete RFC 1995-compliant incremental zone transfer implementation
  - **Zone History**: Maintains version history for efficient incremental transfers
  - **Automatic Fallback**: Falls back to AXFR when incremental history is not available
  - **Configurable Response Mode**: Can be configured to always send full zone transfers (AXFR format) in response to IXFR requests if needed
  - **Robust Diff Calculation**: Ensures complete diff sequences are calculated, including transitions from history to current cache
- **TCP Zone Transfers**: Full support for TCP-based zone transfers with proper connection handling

### Tested Compatibility

- **Knot DNS**: Fully compatible with Knot DNS slave servers
  - Handles SOA queries on TCP before zone transfers
  - Supports multiple queries per TCP connection
  - Proper NOTIFY message handling
  - **IXFR Support**: Full incremental zone transfer support prevents "incomplete history" errors
- **BIND**: Compatible with BIND master and slave servers
- **Other RFC-compliant DNS servers**: Should work with any DNS server that follows RFC 1995 and RFC 1996

## Security

- **XFER Whitelist Enforcement**: Critical for security - only whitelisted IPs can transfer zones
- **Automatic Slave Whitelisting**: Ensures configured slaves can always transfer
- **Health Check ACL**: Only configured IP addresses/networks can query the DNS server for health checks
- **IP Validation**: Prevents unauthorized zone transfers and health check queries
- **NOTIFY Validation**: Only accepts NOTIFY messages from configured upstream master IPs
- **Systemd Security**: The included systemd service file includes security hardening options (`NoNewPrivileges`, `PrivateTmp`)

## Troubleshooting

### Slave Servers Not Receiving Updates

If your slave servers (e.g., Knot DNS) are not receiving zone updates:

1. **Check NOTIFY Configuration**: Ensure slave IPs are correctly configured in the `Slaves` array
2. **Verify Network Connectivity**: Ensure UDP port 53 is open between FilterDNS and slave servers
3. **Check Logs**: Look for NOTIFY-related log messages:
   - `"Successfully notified slave {Ip}:{Port} for zone {Zone}"` - NOTIFY sent successfully
   - `"Failed to notify slave {Ip}:{Port}"` - NOTIFY failed (check network/firewall)
   - `"Timeout waiting for NOTIFY response"` - Slave didn't respond (may be normal if slave doesn't send response)
4. **Verify Slave Configuration**: Ensure your slave DNS server is configured to accept NOTIFY messages from FilterDNS's IP address
5. **Check Serial Numbers**: Verify that zone serial numbers are actually changing on the upstream master

### Connection Reset Errors

If you see "connection reset" errors in slave server logs:

1. **TCP Port Access**: Ensure TCP port 53 is accessible from slave servers
2. **Firewall Rules**: Check that both UDP and TCP port 53 are open
3. **SOA Queries**: FilterDNS now handles SOA queries on TCP that some DNS servers send before zone transfers
4. **Connection Handling**: FilterDNS supports multiple queries per TCP connection and proper connection lifecycle management

### Zone Transfer Failures

If zone transfers are failing:

1. **Whitelist Check**: Verify the slave IP is in the `XferWhitelist` or `Slaves` configuration
2. **Zone Name Matching**: Ensure zone names match exactly (case-insensitive, but trailing dots are normalized)
3. **Upstream Availability**: Check that the upstream master server is accessible and responding
4. **Logs**: Check FilterDNS logs for detailed error messages about transfer failures

### IXFR "Incomplete History" Errors

If your slave servers (e.g., Knot DNS) report "incomplete history" and fall back to AXFR:

1. **History Storage**: Ensure `DataDirectory` is configured and writable
2. **History Depth**: Check that `DefaultIxfrHistoryDepth` or per-zone `IxfrHistoryDepth` is sufficient
   - Default is 20 versions, which should cover most scenarios
   - Increase if zones update very frequently
3. **History Files**: Check that history files exist in `{DataDirectory}/history/`
   - Files should be named `{zonename}.json`
   - History builds up over time as zones are updated
4. **First Transfer**: On the first transfer after enabling IXFR, history may not be available yet - this is normal and will build up over time
5. **Logs**: Check FilterDNS logs for messages like:
   - `"IXFR request for zone {Zone}: client serial {Serial}, server serial {Serial}"`
   - `"history not available for serial {Serial}, falling back to AXFR"` - indicates history needs to build up
   - `"IXFR for zone {Zone}: sending incremental changes"` - indicates successful IXFR

### IXFR Zone Data Corruption or Missing Records

If you notice zones losing records after IXFR transfers (e.g., zone size dropping from 460+ records to 63):

1. **Check Logs**: Look for warning messages like:
   - `"SUSPICIOUS: Large number of deletions ({Deletions}) vs current zone size ({CurrentCount})"` - indicates potential diff calculation issues
   - `"IXFR response: ... Deletions={Deletions} | Additions={Additions}"` - review the change counts
2. **Use FullZone Mode**: If you suspect incremental transfers are causing data loss, switch to full zone transfers:
   ```json
   {
     "Server": {
       "IxfrResponseMode": "FullZone"
     }
   }
   ```
   This ensures complete zone data is always transferred, though it's less efficient than incremental transfers.
3. **Verify History**: Check that zone history is being properly maintained:
   - Ensure `DataDirectory` is writable
   - Check that history files are being created and updated
   - Verify that `DefaultIxfrHistoryDepth` is sufficient for your update frequency
4. **Recent Fixes**: Recent improvements ensure that:
   - The current zone version (even if not yet saved to history) is included in diff calculations
   - Validation warnings are logged when suspicious deletion counts are detected
   - Complete diff sequences are calculated from client serial to server serial

### NOTIFY Messages Not Working

If NOTIFY messages aren't being sent or received:

1. **RFC 1996 Compliance**: FilterDNS sends RFC 1996-compliant NOTIFY messages (Opcode 4, RD bit = 0)
2. **Upstream NOTIFY**: FilterDNS receives NOTIFY from upstream masters and automatically triggers updates
3. **Slave NOTIFY**: FilterDNS sends NOTIFY to configured slaves after zone updates
4. **Check Logs**: Look for NOTIFY-related log entries to diagnose issues

### Slaves Out of Sync During Rapid Updates

If slaves get out of sync when your master server experiences many quick zone updates in succession:

**Symptoms:**
- Slave servers miss intermediate zone versions
- IXFR requests fail with "version not found" errors
- Slaves fall back to AXFR frequently during busy periods
- Zone data appears inconsistent across slaves

**Solutions:**

1. **Enable NOTIFY Debouncing** (recommended for environments with frequent updates):
   ```json
   {
     "Server": {
       "NotifyDebounceMs": 500
     }
   }
   ```
   This waits for a quiet period before processing NOTIFYs, coalescing rapid updates into a single zone fetch.

2. **Set Minimum Slave NOTIFY Interval** (prevents flooding slaves):
   ```json
   {
     "Server": {
       "MinSlaveNotifyIntervalMs": 2000
     }
   }
   ```
   This enforces a minimum 2-second gap between NOTIFYs sent to slaves, giving them time to process each update.

3. **Increase IXFR History Depth** (prevents version pruning during rapid updates):
   ```json
   {
     "Server": {
       "DefaultIxfrHistoryDepth": 50,
       "EnableDynamicHistoryDepth": true
     }
   }
   ```
   - `DefaultIxfrHistoryDepth`: Increase base history depth
   - `EnableDynamicHistoryDepth`: Automatically increases depth during rapid update periods

4. **Per-Zone Configuration** for zones with frequent updates:
   ```json
   {
     "Zones": [
       {
         "Name": "frequently-updated.example.com",
         "NotifyDebounceMs": 1000,
         "MinSlaveNotifyIntervalMs": 3000,
         "IxfrHistoryDepth": 100
       }
     ]
   }
   ```

**Check Logs** for rapid update handling:
- `"Zone {Zone} is in rapid update period ({Count} updates in last {Window}s)"` - Rapid updates detected
- `"Debouncing zone {Zone} for {Ms}ms"` - NOTIFY debouncing active
- `"Delaying NOTIFY to slaves for zone {Zone} by {Ms}ms"` - Rate limiting active
- `"Dynamic history depth for zone {Zone}: {Base} -> {Dynamic}"` - History depth expanded

**Understanding the Problem:**

When a master DNS server makes many rapid changes (e.g., automated updates, bulk record changes), several issues can occur:

1. **NOTIFY Cascade**: Each master NOTIFY triggers a zone fetch, cache update, and slave NOTIFY. With rapid updates, this creates a cascade that can overwhelm slaves.

2. **History Pruning**: With limited history depth, older versions are pruned before slaves can request IXFR for them, forcing AXFR fallback.

3. **Race Conditions**: Zone versions can change between when a slave receives NOTIFY and when it requests IXFR, causing "version not found" errors.

The rapid update handling features address all these issues by:
- **Debouncing**: Waiting for updates to settle before processing
- **Rate Limiting**: Spacing out NOTIFYs to slaves
- **Dynamic History**: Keeping more versions during busy periods
- **Version Locking**: Taking snapshots during zone transfers to ensure consistency

## Logging

FilterDNS uses Serilog for logging and supports:
- **Console output** (always enabled)
- **Remote logging to Seq** (optional, configured in `appsettings.json`)
- Configurable log levels via `appsettings.json`

### Seq Configuration

To enable Seq logging, add the following to your `appsettings.json`:

```json
{
  "Server": {
    "Seq": {
      "Enabled": true,
      "ServerUrl": "https://your-seq-server.com",
      "ApiKey": "your-api-key-here"
    }
  }
}
```

- **Enabled**: Set to `true` to enable Seq logging, `false` to disable
- **ServerUrl**: The URL of your Seq server (e.g., `https://log.example.com`)
- **ApiKey**: Your Seq API key for authentication

If Seq is not configured or disabled, only console logging will be used.

### Log Levels

Available log levels: `Trace`, `Debug`, `Information`, `Warning`, `Error`, `Critical`

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**. See the [LICENSE](LICENSE) file for the full license text.

### What this means:

- ✅ **Free to use**: You can use this software for any purpose
- ✅ **Free to modify**: You can change the code to suit your needs
- ✅ **Free to distribute**: You can share the software with others
- ⚠️ **Copyleft**: If you distribute modified versions, you must also license them under GPL-3.0
- ⚠️ **Source code required**: You must provide source code when distributing binaries

### Third-Party Dependencies

FilterDNS uses third-party NuGet packages that are licensed under permissive licenses (MIT, Apache 2.0) compatible with GPL-3.0. See [THIRD-PARTY-LICENSES.md](THIRD-PARTY-LICENSES.md) for a complete list of dependencies and their licenses.

For more information about GPL-3.0 and alternative license options, see [LICENSE-OPTIONS.md](LICENSE-OPTIONS.md).
