# Frequently Asked Questions (FAQ)

Common questions about FilterDNS Proxy.

## General Questions

### What is FilterDNS Proxy?

FilterDNS Proxy is a .NET 10-based DNS master proxy server that serves zone transfers (AXFR/IXFR) to configured slave DNS servers, with IP whitelisting, NOTIFY support, and selective record filtering.

### What problem does FilterDNS solve?

FilterDNS allows you to sanitize and transform DNS zones before serving them to public-facing slave DNS servers. Common use cases include:
- Hiding internal nameservers (e.g., Active Directory) from public DNS
- Filtering private IP addresses from Internet zones
- Separating internal and external DNS views
- Controlling zone transfer access

### Is FilterDNS a DNS server?

FilterDNS acts as a **DNS master proxy** - it sits between your upstream master DNS (e.g., Active Directory) and your public slave DNS servers. It filters and transforms zones before serving them to slaves.

### What DNS servers does FilterDNS work with?

FilterDNS is compatible with:
- **Knot DNS** - Fully tested and supported
- **BIND** - Compatible with BIND master and slave servers
- **Other RFC-compliant DNS servers** - Should work with any server following RFC 1995 and RFC 1996

## Installation & Setup

### What are the system requirements?

- **Operating System**: Linux (tested on Ubuntu, Debian, RHEL/CentOS)
- **Architecture**: AMD64 (x86_64)
- **.NET Runtime**: .NET 10 runtime (included in deployment package)
- **Privileges**: Root access required to bind to port 53

### Do I need to install .NET separately?

No, the deployment package includes the .NET runtime. You don't need to install .NET separately.

### Can I run FilterDNS without root privileges?

No, FilterDNS requires root privileges to bind to port 53 (the standard DNS port). You can run it on a different port, but then slave servers won't be able to use the standard DNS port.

### How do I update FilterDNS?

1. Stop the service: `sudo systemctl stop filter-dns`
2. Backup your configuration: `cp appsettings.json appsettings.json.backup`
3. Extract the new version
4. Restore your configuration
5. Start the service: `sudo systemctl start filter-dns`

See [[Installation]] for detailed instructions.

## Configuration

### How do I configure zones?

Edit `appsettings.json` and add zones to the `Zones` array. See [[Configuration]] for detailed configuration options.

### Can I configure multiple zones?

Yes, you can configure multiple zones in the `Zones` array. Each zone can have different upstream masters, filtering rules, and slave servers.

### What's the difference between Slaves and XferWhitelist?

- **Slaves**: DNS servers that receive NOTIFY messages and are automatically whitelisted for zone transfers
- **XferWhitelist**: Additional IPs/networks allowed for zone transfers (e.g., monitoring tools)

### How do I enable private IP filtering?

Set `FilterPrivateIPs: true` in your zone configuration. See [[Configuration]] for details.

### Can I use custom private IP ranges?

Yes, use the `PrivateIPRanges` array to specify custom CIDR ranges. If empty, FilterDNS uses default RFC 1918 ranges.

### What happens if I don't configure SoaRname?

If `SoaRname` is not configured, FilterDNS preserves the original rname from the upstream zone.

## Zone Transfers

### Does FilterDNS support IXFR?

Yes, FilterDNS has full RFC 1995-compliant IXFR support with zone history tracking.

### What's the difference between Incremental and FullZone IXFR modes?

- **Incremental**: Sends only the changes between zone versions (more efficient)
- **FullZone**: Always sends the complete zone (more reliable, less efficient)

Use `FullZone` mode if you experience zone data corruption with incremental transfers.

### How does zone history work?

FilterDNS maintains a history of zone versions for IXFR support. History is stored in JSON format and persists across restarts. You can configure history depth per zone or globally.

### Why do I get "incomplete history" errors?

This usually means:
1. History hasn't built up yet (normal on first transfer)
2. History depth is too low for your update frequency
3. History files are missing or corrupted

See [[Troubleshooting]] for solutions.

### Can I disable IXFR and use only AXFR?

Yes, set `IxfrResponseMode: "FullZone"` in server configuration. This makes FilterDNS always send full zone transfers (AXFR format) in response to IXFR requests.

## NOTIFY Messages

### Does FilterDNS send NOTIFY messages?

Yes, FilterDNS sends RFC 1996-compliant NOTIFY messages to all configured slave servers when zones are updated.

### Does FilterDNS receive NOTIFY messages?

Yes, FilterDNS receives and processes NOTIFY messages from upstream master servers, automatically triggering zone updates.

### How do I verify NOTIFY is working?

Check FilterDNS logs for NOTIFY-related messages:
```bash
sudo journalctl -u filter-dns | grep -i notify
```

You should see messages like "Successfully notified slave {Ip}:{Port} for zone {Zone}".

## Filtering

### What records does FilterDNS filter?

FilterDNS can filter/modify:
- **SOA records**: Modifies mname (primary nameserver) and optionally rname
- **NS records**: Completely replaces all NS records with configured ones
- **A/AAAA records**: Optionally filters records pointing to private IP addresses

### Does FilterDNS preserve serial numbers?

Yes, FilterDNS preserves serial numbers and all other SOA fields (TTL, refresh, retry, expire, minimum).

### Can I filter specific record types?

Currently, FilterDNS filters:
- SOA (modifies mname/rname)
- NS (replaces all)
- A/AAAA (filters private IPs if enabled)

Other record types pass through unchanged.

### What happens to records that don't match filters?

Records that don't match any filter criteria pass through unchanged (except NS records, which are always replaced).

## Security

### How does IP whitelisting work?

FilterDNS enforces IP whitelisting for zone transfers:
- Configured slaves are automatically whitelisted
- Additional IPs can be added via `XferWhitelist`
- Unauthorized transfer requests are refused

### Can I use CIDR notation in whitelists?

Yes, both `XferWhitelist` and `HealthCheckAcl` support CIDR notation:
```json
"XferWhitelist": ["192.0.2.0/24", "2001:db8::/64"]
```

### Does FilterDNS support IPv6?

Yes, FilterDNS fully supports IPv6 for:
- Upstream masters
- Slave servers
- Whitelist entries
- Health check ACLs

## Health Checks

### What are health checks?

Health checks allow monitoring systems to query FilterDNS and receive filtered zone data responses, verifying that filtering is working correctly.

### How do I configure health checks?

Add IP addresses/networks to `HealthCheckAcl` in server configuration:
```json
"HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8"]
```

### What query types are supported for health checks?

Health checks support standard DNS query types: A, AAAA, NS, SOA, and others.

## Troubleshooting

### How do I check if FilterDNS is running?

```bash
sudo systemctl status filter-dns
```

### How do I view logs?

```bash
# Recent logs
sudo journalctl -u filter-dns -n 100

# Follow logs in real-time
sudo journalctl -u filter-dns -f
```

### How do I test zone transfers?

From a configured slave server:
```bash
dig @filterdns-server example.com AXFR
dig @filterdns-server example.com IXFR=12345
```

### Why aren't my slaves receiving updates?

Check:
1. Slave IPs are configured correctly
2. Network connectivity (UDP port 53)
3. NOTIFY messages in logs
4. Serial numbers are changing on upstream

See [[Troubleshooting]] for detailed solutions.

## Performance

### How often does FilterDNS poll upstream?

Configurable via `UpstreamPollInterval` (default: 300 seconds). FilterDNS also responds to NOTIFY messages immediately.

### Does FilterDNS cache zones?

Yes, filtered zones are cached in memory for fast zone transfer responses. Cache is updated only when upstream zones change.

### How much disk space does zone history use?

Depends on:
- Number of zones
- History depth per zone
- Zone size
- Update frequency

History files are typically small (JSON format). BIND format exports are optional and can be disabled.

## License

### What license is FilterDNS under?

FilterDNS is licensed under **GNU General Public License v3.0 (GPL-3.0)**.

### Can I use FilterDNS commercially?

Yes, GPL-3.0 allows commercial use. However, if you distribute modified versions, you must also license them under GPL-3.0 and provide source code.

## Getting Help

### Where can I get help?

1. Check the [[Troubleshooting]] guide
2. Review the [[Configuration]] documentation
3. Open an issue on GitHub

### How do I report a bug?

Open an issue on GitHub with:
- Description of the problem
- Relevant log excerpts
- Configuration (sanitized)
- Steps to reproduce

### Can I contribute?

Yes! Contributions are welcome. Please open a pull request or issue on GitHub.

## Next Steps

- [[Installation]] - Get started with FilterDNS
- [[Configuration]] - Configure your zones
- [[Use-Cases]] - Common usage scenarios
- [[Troubleshooting]] - Solve common issues
