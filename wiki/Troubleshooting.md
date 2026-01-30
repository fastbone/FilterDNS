# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with FilterDNS Proxy.

## Common Issues

### Slave Servers Not Receiving Updates

**Symptoms:**
- Slave servers don't receive zone updates
- Zones on slaves are outdated
- No NOTIFY messages received

**Solutions:**

1. **Check NOTIFY Configuration**
   ```bash
   # Verify slave IPs are configured correctly
   grep -A 5 "Slaves" appsettings.json
   ```

2. **Verify Network Connectivity**
   ```bash
   # Test UDP port 53 from FilterDNS to slave
   nc -u -v slave-ip 53
   
   # Check firewall rules
   sudo ufw status
   sudo firewall-cmd --list-all
   ```

3. **Check Logs**
   ```bash
   # Look for NOTIFY-related messages
   sudo journalctl -u filter-dns | grep -i notify
   
   # Check for successful NOTIFY
   # Should see: "Successfully notified slave {Ip}:{Port} for zone {Zone}"
   ```

4. **Verify Slave Configuration**
   - Ensure slave DNS server accepts NOTIFY from FilterDNS IP
   - Check slave server logs for NOTIFY messages
   - Verify slave is configured to accept NOTIFY from FilterDNS

5. **Check Serial Numbers**
   ```bash
   # Verify upstream zone serial is changing
   dig @upstream-master example.com SOA
   
   # Check FilterDNS cached serial
   dig @filterdns-server example.com SOA
   ```

### Connection Reset Errors

**Symptoms:**
- Slave server logs show "connection reset" errors
- Zone transfers fail with connection errors
- TCP connections are dropped

**Solutions:**

1. **Check TCP Port Access**
   ```bash
   # Verify TCP port 53 is accessible
   telnet filterdns-server 53
   nc -v filterdns-server 53
   ```

2. **Verify Firewall Rules**
   ```bash
   # Ensure both UDP and TCP port 53 are open
   sudo ufw allow 53/tcp
   sudo ufw allow 53/udp
   
   # For firewalld
   sudo firewall-cmd --permanent --add-service=dns
   sudo firewall-cmd --reload
   ```

3. **Check FilterDNS Logs**
   ```bash
   # Look for connection-related errors
   sudo journalctl -u filter-dns | grep -i "connection\|reset\|tcp"
   ```

4. **Verify SOA Query Handling**
   - FilterDNS handles SOA queries on TCP (some DNS servers send these before transfers)
   - Check that FilterDNS is responding to SOA queries correctly

### Zone Transfer Failures

**Symptoms:**
- Zone transfers are refused
- "Transfer refused" errors in slave logs
- Transfers work from some IPs but not others

**Solutions:**

1. **Check Whitelist Configuration**
   ```bash
   # Verify slave IP is in whitelist
   grep -A 10 "Slaves\|XferWhitelist" appsettings.json
   ```

2. **Verify IP Addresses**
   - Ensure slave IP addresses are correct
   - Check for IPv4 vs IPv6 mismatches
   - Verify CIDR notation is correct for networks

3. **Check Zone Name Matching**
   ```bash
   # Zone names are case-insensitive but must match
   # Trailing dots are normalized
   # Verify zone name in config matches upstream zone name
   ```

4. **Test Zone Transfer Manually**
   ```bash
   # From slave server, test AXFR
   dig @filterdns-server example.com AXFR
   
   # Check FilterDNS logs for transfer attempts
   sudo journalctl -u filter-dns -f
   ```

5. **Verify Upstream Availability**
   ```bash
   # Check upstream master is accessible
   dig @upstream-master example.com SOA
   ping upstream-master-ip
   ```

### IXFR "Incomplete History" Errors

**Symptoms:**
- Slave servers report "incomplete history"
- Slaves fall back to AXFR instead of IXFR
- IXFR transfers fail

**Solutions:**

1. **Check History Storage**
   ```bash
   # Verify data directory exists and is writable
   ls -la data/history/
   
   # Check history files exist
   ls -la data/history/*.json
   ```

2. **Verify History Depth**
   ```json
   {
     "Server": {
       "DefaultIxfrHistoryDepth": 20
     },
     "Zones": [
       {
         "Name": "example.com",
         "IxfrHistoryDepth": 50
       }
     ]
   }
   ```
   - Increase depth if zones update very frequently
   - Default is 20 versions, which should cover most scenarios

3. **Check History Files**
   ```bash
   # Verify history files are being created
   cat data/history/example.com.json | jq '.versions | length'
   
   # Check file permissions
   ls -la data/history/example.com.json
   ```

4. **First Transfer After Enabling IXFR**
   - History builds up over time as zones are updated
   - First transfer may not have history available - this is normal
   - History will be available after a few zone updates

5. **Check Logs**
   ```bash
   # Look for IXFR-related messages
   sudo journalctl -u filter-dns | grep -i ixfr
   
   # Should see messages like:
   # "IXFR request for zone {Zone}: client serial {Serial}, server serial {Serial}"
   # "IXFR for zone {Zone}: sending incremental changes"
   ```

### IXFR Zone Data Corruption or Missing Records

**Symptoms:**
- Zones lose records after IXFR transfers
- Zone size drops unexpectedly (e.g., from 460+ records to 63)
- Records missing after incremental transfer

**Solutions:**

1. **Check Logs for Warnings**
   ```bash
   # Look for suspicious deletion warnings
   sudo journalctl -u filter-dns | grep -i "SUSPICIOUS\|deletion"
   
   # Should see warnings like:
   # "SUSPICIOUS: Large number of deletions ({Deletions}) vs current zone size ({CurrentCount})"
   ```

2. **Switch to FullZone Mode**
   ```json
   {
     "Server": {
       "IxfrResponseMode": "FullZone"
     }
   }
   ```
   - This ensures complete zone data is always transferred
   - Less efficient but more reliable
   - Use if incremental transfers cause data loss

3. **Verify History Integrity**
   ```bash
   # Check history files are valid JSON
   cat data/history/example.com.json | jq .
   
   # Verify zone versions are being saved
   cat data/history/example.com.json | jq '.versions | length'
   ```

4. **Check History Depth**
   - Ensure `DefaultIxfrHistoryDepth` or per-zone `IxfrHistoryDepth` is sufficient
   - Increase if zones update very frequently

### NOTIFY Messages Not Working

**Symptoms:**
- NOTIFY messages not sent to slaves
- NOTIFY messages not received from upstream
- Zones not updating automatically

**Solutions:**

1. **Verify NOTIFY Configuration**
   ```json
   {
     "Zones": [
       {
         "Name": "example.com",
         "Slaves": [
           {"Ip": "192.0.2.10", "Port": 53}
         ]
       }
     ]
   }
   ```

2. **Check RFC 1996 Compliance**
   - FilterDNS sends RFC 1996-compliant NOTIFY (Opcode 4, RD bit = 0)
   - Verify slave DNS server supports RFC 1996 NOTIFY

3. **Test NOTIFY Manually**
   ```bash
   # Check FilterDNS logs for NOTIFY attempts
   sudo journalctl -u filter-dns | grep -i notify
   
   # Should see:
   # "Successfully notified slave {Ip}:{Port} for zone {Zone}"
   # or
   # "Failed to notify slave {Ip}:{Port}"
   ```

4. **Verify Upstream NOTIFY**
   - FilterDNS receives NOTIFY from upstream masters
   - Check that upstream master is configured to send NOTIFY to FilterDNS
   - Verify FilterDNS IP is in upstream master's NOTIFY list

### Service Won't Start

**Symptoms:**
- systemd service fails to start
- "Permission denied" errors
- Port 53 already in use

**Solutions:**

1. **Check Port 53 Availability**
   ```bash
   # Check if port 53 is already in use
   sudo netstat -tulpn | grep :53
   sudo lsof -i :53
   
   # Stop conflicting services
   sudo systemctl stop systemd-resolved  # Ubuntu/Debian
   sudo systemctl stop named             # BIND
   ```

2. **Check Permissions**
   ```bash
   # FilterDNS needs root to bind to port 53
   # Verify service file has correct user
   cat /etc/systemd/system/filter-dns.service
   ```

3. **Check Configuration File**
   ```bash
   # Verify appsettings.json is valid JSON
   cat appsettings.json | jq .
   
   # Check for syntax errors
   ```

4. **Check Logs**
   ```bash
   # Check systemd logs
   sudo journalctl -u filter-dns -n 50
   
   # Check for specific errors
   sudo journalctl -u filter-dns | grep -i error
   ```

### Health Checks Not Working

**Symptoms:**
- Health check queries return no response
- Queries from monitoring systems fail

**Solutions:**

1. **Verify HealthCheckAcl Configuration**
   ```json
   {
     "Server": {
       "HealthCheckAcl": ["127.0.0.1", "10.0.0.0/8", "192.168.1.100"]
     }
   }
   ```

2. **Test from Whitelisted IP**
   ```bash
   # Query from whitelisted IP
   dig @filterdns-server www.example.com A
   dig @filterdns-server example.com NS
   dig @filterdns-server example.com SOA
   ```

3. **Check Zone Configuration**
   - Verify zone is configured in `appsettings.json`
   - Check zone name matches queried domain

4. **Check Logs**
   ```bash
   # Look for health check queries
   sudo journalctl -u filter-dns | grep -i "health\|query"
   ```

## Diagnostic Commands

### Check Service Status
```bash
sudo systemctl status filter-dns
```

### View Recent Logs
```bash
sudo journalctl -u filter-dns -n 100
```

### Follow Logs in Real-Time
```bash
sudo journalctl -u filter-dns -f
```

### Test Zone Transfer
```bash
# From slave server
dig @filterdns-server example.com AXFR
dig @filterdns-server example.com IXFR=12345
```

### Check Zone History
```bash
# List zone history files
ls -la data/history/

# View zone history
cat data/history/example.com.json | jq .

# Count zone versions
cat data/history/example.com.json | jq '.versions | length'
```

### Verify Configuration
```bash
# Validate JSON syntax
cat appsettings.json | jq .

# Check specific zone configuration
cat appsettings.json | jq '.Zones[] | select(.Name == "example.com")'
```

### Network Diagnostics
```bash
# Test UDP connectivity
nc -u -v filterdns-server 53

# Test TCP connectivity
nc -v filterdns-server 53

# Check listening ports
sudo netstat -tulpn | grep :53
```

## Getting More Help

If you're still experiencing issues:

1. **Check the [[FAQ]]** for answers to common questions
2. **Review logs** with increased verbosity:
   ```json
   {
     "Server": {
       "LogLevel": "Debug"
     }
   }
   ```
3. **Open an issue** on GitHub with:
   - Description of the problem
   - Relevant log excerpts
   - Configuration (sanitized)
   - Steps to reproduce

## Next Steps

- [[Configuration]] - Review configuration options
- [[Architecture]] - Understand how FilterDNS works
- [[Use-Cases]] - See common usage scenarios
