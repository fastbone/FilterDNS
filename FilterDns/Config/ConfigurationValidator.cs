using System.Net;
using System.Text.RegularExpressions;
using FilterDns.Net;
using FilterDns.Whitelist;
using Microsoft.Extensions.Logging;

namespace FilterDns.Config;

public static class ConfigurationValidator
{
    private static readonly string[] IxfrModes = ["Incremental", "FullZone"];

    public static void Validate(AppConfiguration config)
    {
        if (config.Zones == null || config.Zones.Count == 0)
        {
            throw new InvalidOperationException("No zones configured");
        }

        ValidateServer(config.Server);

        var seenZones = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hardeningEnabled = config.Server.Security?.SecurityHardeningEnabled ?? true;
        foreach (var zone in config.Zones)
        {
            ValidateZone(zone, config.Server.Security, hardeningEnabled);
            var canonicalName = zone.Name.TrimEnd('.').ToLowerInvariant();
            if (!seenZones.Add(canonicalName))
            {
                throw new InvalidOperationException($"Duplicate zone configured: {zone.Name}");
            }
        }
    }

    private static void ValidateServer(ServerConfig server)
    {
        if (!IPAddress.TryParse(server.ListenAddress, out _))
        {
            throw new InvalidOperationException($"Server.ListenAddress is invalid: {server.ListenAddress}");
        }

        ValidatePort(server.ListenPort, "Server.ListenPort");
        ValidateLogLevel(server.LogLevel, "Server.LogLevel");

        var logging = server.Logging ?? new LoggingConfig
        {
            DefaultLevel = server.LogLevel,
            OperationsLevel = server.LogLevel,
            DebugLevel = server.LogLevel
        };
        ValidateLogLevel(logging.DefaultLevel, "Server.Logging.DefaultLevel");
        ValidateLogLevel(logging.OperationsLevel, "Server.Logging.OperationsLevel");
        ValidateLogLevel(logging.DebugLevel, "Server.Logging.DebugLevel");
        foreach (var category in logging.Categories)
        {
            ValidateLogLevel(category.Value, $"Server.Logging.Categories[{category.Key}]");
        }

        if (!IxfrModes.Contains(server.IxfrResponseMode, StringComparer.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException($"Server.IxfrResponseMode must be one of: {string.Join(", ", IxfrModes)}");
        }

        _ = new IpWhitelist(server.HealthCheckAcl ?? []);

        if (server.Email?.Enabled == true)
        {
            ValidateEmail(server.Email);
        }
    }

    private static void ValidateZone(ZoneConfig zone, SecurityConfig? securityConfig, bool hardeningEnabled)
    {
        if (string.IsNullOrEmpty(zone.Ns1) || string.IsNullOrEmpty(zone.Ns2))
        {
            throw new InvalidOperationException($"Zone {zone.Name} must have NS1 and NS2 configured");
        }

        if (hardeningEnabled)
        {
            ValidateZoneName(zone.Name, securityConfig);
        }

        ValidateEndpoint(zone.Upstream, $"Zone {zone.Name}.Upstream");
        _ = new IpWhitelist(zone.XferWhitelist ?? []);
        foreach (var slave in zone.Slaves)
        {
            if (!slave.IsValid())
            {
                throw new InvalidOperationException($"Zone {zone.Name} has invalid slave: {slave.Ip}:{slave.Port}");
            }
        }

        foreach (var range in zone.PrivateIPRanges ?? [])
        {
            ValidateIpOrCidr(range, $"Zone {zone.Name}.PrivateIPRanges");
        }
    }

    private static void ValidateEndpoint(string endpoint, string key)
    {
        var parts = endpoint.Split(':');
        if (parts.Length == 0 || !IPAddress.TryParse(parts[0], out _))
        {
            throw new InvalidOperationException($"{key} must start with a valid IP address");
        }

        if (parts.Length > 1)
        {
            if (!int.TryParse(parts[1], out var port))
            {
                throw new InvalidOperationException($"{key} has invalid port: {parts[1]}");
            }
            ValidatePort(port, key);
        }
    }

    private static void ValidateIpOrCidr(string value, string key)
    {
        if (IPAddress.TryParse(value, out _))
        {
            return;
        }

        var parts = value.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var networkIp) || !int.TryParse(parts[1], out var prefixLength))
        {
            throw new InvalidOperationException($"{key} contains invalid IP/CIDR: {value}");
        }

        try
        {
            _ = new CidrRange(networkIp, prefixLength);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidOperationException($"{key} contains invalid IP/CIDR: {value}", ex);
        }
    }

    private static void ValidatePort(int port, string key)
    {
        if (port <= 0 || port > 65535)
        {
            throw new InvalidOperationException($"{key} must be between 1 and 65535");
        }
    }

    private static void ValidateLogLevel(string level, string key)
    {
        if (!Enum.TryParse<LogLevel>(level, ignoreCase: true, out _))
        {
            throw new InvalidOperationException($"{key} has invalid log level '{level}'");
        }
    }

    private static void ValidateEmail(EmailConfig email)
    {
        if (string.IsNullOrWhiteSpace(email.SmtpServer))
        {
            throw new InvalidOperationException("Server.Email.SmtpServer is required when email is enabled");
        }
        ValidatePort(email.SmtpPort, "Server.Email.SmtpPort");
        if (string.IsNullOrWhiteSpace(email.FromAddress))
        {
            throw new InvalidOperationException("Server.Email.FromAddress is required when email is enabled");
        }
        if (string.IsNullOrWhiteSpace(email.ToAddress))
        {
            throw new InvalidOperationException("Server.Email.ToAddress is required when email is enabled");
        }
    }

    private static void ValidateZoneName(string zoneName, SecurityConfig? securityConfig)
    {
        if (string.IsNullOrWhiteSpace(zoneName))
        {
            throw new ArgumentException("Zone name cannot be null or empty", nameof(zoneName));
        }

        var maxZoneNameLength = securityConfig?.MaxZoneNameLength ?? 253;
        var normalized = zoneName.TrimEnd('.').ToLowerInvariant();
        if (normalized.Length > maxZoneNameLength)
        {
            throw new ArgumentException($"Zone name length ({normalized.Length}) exceeds maximum ({maxZoneNameLength})", nameof(zoneName));
        }
        if (string.IsNullOrEmpty(normalized))
        {
            throw new ArgumentException("Zone name cannot be empty or only dots", nameof(zoneName));
        }
        if (normalized.Contains(".."))
        {
            throw new ArgumentException("Zone name contains consecutive dots", nameof(zoneName));
        }

        var labels = normalized.Split('.');
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
            {
                throw new ArgumentException("Zone name contains empty label", nameof(zoneName));
            }
            if (label.Length > 63)
            {
                throw new ArgumentException($"Label '{label}' length ({label.Length}) exceeds maximum (63)", nameof(zoneName));
            }
            if (label.StartsWith('-') || label.EndsWith('-'))
            {
                throw new ArgumentException($"Label '{label}' cannot start or end with hyphen", nameof(zoneName));
            }
            if (!Regex.IsMatch(label, @"^[a-z0-9_-]+$", RegexOptions.IgnoreCase))
            {
                throw new ArgumentException($"Label '{label}' contains invalid characters (only alphanumeric, hyphen, underscore allowed)", nameof(zoneName));
            }
        }

        var byteLength = System.Text.Encoding.UTF8.GetByteCount(normalized);
        if (byteLength > 253)
        {
            throw new ArgumentException($"Zone name byte length ({byteLength}) exceeds maximum (253)", nameof(zoneName));
        }
    }
}
