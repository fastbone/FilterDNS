# Installation Guide

This guide will help you install and set up FilterDNS Proxy on your system.

## Requirements

- **Operating System**: Linux (tested on Ubuntu, Debian, RHEL/CentOS)
- **Architecture**: AMD64 (x86_64)
- **.NET Runtime**: .NET 10 runtime (included in deployment package)
- **Privileges**: Root access required to bind to port 53

## Installation Methods

### Method 1: Using the Deployment Package (Recommended)

1. **Download the latest release** from the GitHub releases page

2. **Extract the package**:
   ```bash
   tar -xzf filter-dns-YYYYMMDD_HHMMSS.tar.gz
   cd filter-dns-YYYYMMDD_HHMMSS
   ```

3. **Configure the application**:
   ```bash
   cp appsettings.example.json appsettings.json
   # Edit appsettings.json with your configuration
   nano appsettings.json
   ```

4. **Install as a systemd service**:
   ```bash
   sudo cp filter-dns.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable filter-dns
   sudo systemctl start filter-dns
   ```

5. **Verify the service is running**:
   ```bash
   sudo systemctl status filter-dns
   ```

### Method 2: Manual Execution

1. **Extract the package**:
   ```bash
   tar -xzf filter-dns-YYYYMMDD_HHMMSS.tar.gz
   cd filter-dns-YYYYMMDD_HHMMSS
   ```

2. **Configure the application**:
   ```bash
   cp appsettings.example.json appsettings.json
   # Edit appsettings.json with your configuration
   nano appsettings.json
   ```

3. **Run FilterDNS**:
   ```bash
   sudo ./FilterDns
   ```

   > **Note**: Root privileges are required to bind to port 53 (standard DNS port)

## Building from Source

If you want to build FilterDNS from source:

1. **Install .NET 10 SDK**:
   ```bash
   # Ubuntu/Debian
   wget https://dot.net/v1/dotnet-install.sh
   chmod +x dotnet-install.sh
   ./dotnet-install.sh --version 10.0.0
   
   # Or use your distribution's package manager
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/filter-dns.git
   cd filter-dns
   ```

3. **Build the project**:
   ```bash
   ./build.sh
   ```

4. **Deploy**:
   ```bash
   ./deploy.sh
   ```

The build output will be in `build/linux-x64/` and the deployment package in `deploy/`.

## Post-Installation

### 1. Configure Firewall Rules

Ensure UDP and TCP port 53 are open:

```bash
# For UFW (Ubuntu)
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# For firewalld (RHEL/CentOS)
sudo firewall-cmd --permanent --add-service=dns
sudo firewall-cmd --reload

# For iptables
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
```

### 2. Verify Configuration

Test your configuration:

```bash
# Check if FilterDNS is listening
sudo netstat -tulpn | grep :53

# Check logs
sudo journalctl -u filter-dns -f
```

### 3. Test Zone Transfer

From a configured slave server:

```bash
# Test AXFR
dig @filterdns-server-ip example.com AXFR

# Test IXFR (requires history)
dig @filterdns-server-ip example.com IXFR=12345
```

## Directory Structure

After installation, FilterDNS uses the following directories:

```
/opt/filter-dns/              # Installation directory (if installed to /opt)
├── FilterDns                  # Main executable
├── appsettings.json          # Configuration file
├── data/                     # Data directory (default: ./data)
│   ├── history/              # Zone history files
│   │   ├── example.com.json  # Zone history database
│   │   └── zones/            # BIND format zone exports
│   │       └── example.com_2026012017.zone
└── logs/                     # Log files (if file logging enabled)
```

## Updating FilterDNS

To update to a newer version:

1. **Stop the service**:
   ```bash
   sudo systemctl stop filter-dns
   ```

2. **Backup your configuration**:
   ```bash
   cp appsettings.json appsettings.json.backup
   ```

3. **Extract the new version**:
   ```bash
   tar -xzf filter-dns-NEWVERSION.tar.gz
   cd filter-dns-NEWVERSION
   ```

4. **Restore your configuration**:
   ```bash
   cp ../filter-dns-OLDVERSION/appsettings.json .
   ```

5. **Update the service file** (if changed):
   ```bash
   sudo cp filter-dns.service /etc/systemd/system/
   sudo systemctl daemon-reload
   ```

6. **Start the service**:
   ```bash
   sudo systemctl start filter-dns
   ```

## Uninstallation

To remove FilterDNS:

1. **Stop and disable the service**:
   ```bash
   sudo systemctl stop filter-dns
   sudo systemctl disable filter-dns
   ```

2. **Remove the service file**:
   ```bash
   sudo rm /etc/systemd/system/filter-dns.service
   sudo systemctl daemon-reload
   ```

3. **Remove the application directory**:
   ```bash
   sudo rm -rf /opt/filter-dns  # or wherever you installed it
   ```

## Next Steps

- [[Configuration]] - Configure your zones and settings
- [[Use-Cases]] - Learn about common usage scenarios
- [[Architecture]] - Understand how FilterDNS works
