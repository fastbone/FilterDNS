using FilterDns.Alert;
using FilterDns.Config;
using FilterDns.Export;
using FilterDns.Filter;
using FilterDns.Proxy;
using FilterDns.Upstream;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Serilog;
using Serilog.Extensions.Logging;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace FilterDns;

class Program
{
    static async Task Main(string[] args)
    {
        // Check for export command (supports both "export" and "--export")
        if (args.Length > 0 && (args[0] == "export" || args[0] == "--export"))
        {
            await HandleExportCommandAsync(args);
            Environment.Exit(0);
            return;
        }

        // Load configuration
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        var appConfig = new AppConfiguration();
        configuration.Bind(appConfig);

        // Audit log configuration load if enabled
        if (appConfig.Server.Security?.EnableAuditLogging == true && 
            appConfig.Server.Security?.AuditLogConfigChanges == true)
        {
            Console.WriteLine($"[AUDIT] Configuration loaded from appsettings.json at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        }

        // Validate configuration
        ValidateConfiguration(appConfig);

        // Configure logging
        var loggingConfig = appConfig.Server.Logging ?? new LoggingConfig();
        
        // Backward compatibility: if Logging config is not provided, use old LogLevel setting
        if (appConfig.Server.Logging == null)
        {
            loggingConfig.DefaultLevel = appConfig.Server.LogLevel;
            loggingConfig.OperationsLevel = appConfig.Server.LogLevel;
            // For debug level, use Debug if old LogLevel was Debug or lower, otherwise use the same level
            var oldLogLevel = Enum.Parse<LogLevel>(appConfig.Server.LogLevel);
            loggingConfig.DebugLevel = oldLogLevel <= LogLevel.Debug ? "Debug" : appConfig.Server.LogLevel;
        }

        var defaultLogLevel = Enum.Parse<LogLevel>(loggingConfig.DefaultLevel);
        var operationsLogLevel = Enum.Parse<LogLevel>(loggingConfig.OperationsLevel);
        var debugLogLevel = Enum.Parse<LogLevel>(loggingConfig.DebugLevel);

        // Configure Serilog with granular log levels
        var loggerConfig = new LoggerConfiguration()
            .MinimumLevel.Is(ConvertLogLevel(defaultLogLevel))
            .Enrich.WithProperty("Application", "FilterDNS")
            .WriteTo.Console();

        // Apply per-category log level overrides
        foreach (var category in loggingConfig.Categories)
        {
            if (Enum.TryParse<LogLevel>(category.Value, out var categoryLogLevel))
            {
                loggerConfig.MinimumLevel.Override(category.Key, ConvertLogLevel(categoryLogLevel));
            }
        }

        // Add Seq sink if configured
        if (appConfig.Server.Seq != null && 
            appConfig.Server.Seq.Enabled && 
            !string.IsNullOrWhiteSpace(appConfig.Server.Seq.ServerUrl) &&
            !string.IsNullOrWhiteSpace(appConfig.Server.Seq.ApiKey))
        {
            loggerConfig.WriteTo.Seq(
                serverUrl: appConfig.Server.Seq.ServerUrl,
                apiKey: appConfig.Server.Seq.ApiKey,
                restrictedToMinimumLevel: ConvertLogLevel(defaultLogLevel));
        }

        // Create email alert service first if configured (before creating logger)
        EmailAlertService? emailAlertService = null;
        if (appConfig.Server.Email != null && 
            appConfig.Server.Email.Enabled && 
            !string.IsNullOrWhiteSpace(appConfig.Server.Email.SmtpServer) &&
            !string.IsNullOrWhiteSpace(appConfig.Server.Email.ToAddress))
        {
            // Create a temporary logger configuration just for email alert service initialization
            var tempLoggerConfig = new LoggerConfiguration()
                .MinimumLevel.Is(ConvertLogLevel(defaultLogLevel))
                .WriteTo.Console();
            var tempLogger = tempLoggerConfig.CreateLogger();
            var emailLogger = new SerilogLoggerFactory(tempLogger).CreateLogger<EmailAlertService>();
            emailAlertService = new EmailAlertService(appConfig.Server.Email, emailLogger);
            
            // Add email alert sink for Error and Critical level logs
            loggerConfig.WriteTo.Sink(new EmailAlertSink(emailAlertService), 
                restrictedToMinimumLevel: Serilog.Events.LogEventLevel.Error);
        }

        var serilogLogger = loggerConfig.CreateLogger();

        // Create host
        var host = Host.CreateDefaultBuilder(args)
            .ConfigureLogging(logging =>
            {
                logging.ClearProviders();
                logging.AddConsole();
                logging.AddSerilog(serilogLogger, dispose: true);
                logging.SetMinimumLevel(defaultLogLevel);
                
                // Apply per-category overrides for Microsoft.Extensions.Logging as well
                foreach (var category in loggingConfig.Categories)
                {
                    if (Enum.TryParse<LogLevel>(category.Value, out var categoryLogLevel))
                    {
                        logging.AddFilter(category.Key, categoryLogLevel);
                    }
                }
            })
            .ConfigureServices(services =>
            {
                services.AddSingleton(appConfig);
                if (emailAlertService != null)
                {
                    services.AddSingleton(emailAlertService);
                }
                services.AddHostedService<DnsProxyServer>();
            })
            .Build();

        await host.RunAsync();
    }

    private static async Task HandleExportCommandAsync(string[] args)
    {
        // Skip the command name (export or --export) and get the zone name
        // Both formats use index 1 for zone name: "export zone" or "--export zone"
        if (args.Length < 2)
        {
            Console.WriteLine("Usage: export <zone-name> [output-file]");
            Console.WriteLine("       --export <zone-name> [output-file]");
            Console.WriteLine("  zone-name: Name of the zone to export");
            Console.WriteLine("  output-file: Optional output file path (default: stdout)");
            Environment.Exit(1);
            return;
        }

        var zoneName = args[1];
        var outputFile = args.Length > 2 ? args[2] : null;

        // Load configuration
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .Build();

        var appConfig = new AppConfiguration();
        configuration.Bind(appConfig);

        // Find zone configuration
        var zoneConfig = appConfig.Zones?.FirstOrDefault(z => 
            z.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) ||
            z.Name.TrimEnd('.').Equals(zoneName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase));

        if (zoneConfig == null)
        {
            Console.Error.WriteLine($"Error: Zone '{zoneName}' not found in configuration");
            Environment.Exit(1);
            return;
        }

        try
        {
            // Fetch zone from upstream
            Console.WriteLine($"Fetching zone {zoneName} from upstream {zoneConfig.Upstream}...");
            var timeoutSeconds = appConfig.Server.Security?.ZoneTransferTimeoutSeconds ?? 600;
            var timeout = TimeSpan.FromSeconds(timeoutSeconds);
            var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
            var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneName, CancellationToken.None);
            
            // Apply filters
            var filteredRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneName);
            
            // Export to BIND format
            if (outputFile != null)
            {
                await ZoneExporter.ExportToFileAsync(filteredRecords, zoneName, outputFile);
                Console.WriteLine($"Zone exported to: {outputFile}");
            }
            else
            {
                var bindFormat = ZoneExporter.ExportToBindFormat(filteredRecords, zoneName);
                Console.WriteLine(bindFormat);
            }

            upstreamClient.Dispose();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Error exporting zone: {ex.Message}");
            if (System.Diagnostics.Debugger.IsAttached)
            {
                Console.Error.WriteLine(ex.StackTrace);
            }
            Environment.Exit(1);
        }
    }

    private static void ValidateConfiguration(AppConfiguration config)
    {
        if (config.Zones == null || config.Zones.Count == 0)
        {
            throw new InvalidOperationException("No zones configured");
        }

        var securityConfig = config.Server.Security;
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;

        foreach (var zone in config.Zones)
        {
            if (string.IsNullOrEmpty(zone.Ns1) || string.IsNullOrEmpty(zone.Ns2))
            {
                throw new InvalidOperationException($"Zone {zone.Name} must have NS1 and NS2 configured");
            }

            // Validate zone name if hardening enabled
            if (hardeningEnabled)
            {
                try
                {
                    ValidateZoneName(zone.Name, securityConfig);
                }
                catch (ArgumentException ex)
                {
                    throw new InvalidOperationException($"Invalid zone name '{zone.Name}': {ex.Message}", ex);
                }
            }
            else
            {
                Console.WriteLine($"Warning: Zone name validation skipped for '{zone.Name}' (SecurityHardeningEnabled=false)");
            }
        }
    }

    /// <summary>
    /// Validates a zone name according to RFC 1035 DNS name format.
    /// </summary>
    private static void ValidateZoneName(string zoneName, SecurityConfig? securityConfig)
    {
        if (string.IsNullOrWhiteSpace(zoneName))
        {
            throw new ArgumentException("Zone name cannot be null or empty", nameof(zoneName));
        }

        var maxZoneNameLength = securityConfig?.MaxZoneNameLength ?? 253;
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;

        if (!hardeningEnabled)
        {
            return; // Skip validation if hardening disabled
        }

        // Normalize: remove trailing dot if present, convert to lowercase
        var normalized = zoneName.TrimEnd('.').ToLowerInvariant();

        // Check length (RFC 1035: max 253 bytes for FQDN, but we use characters)
        // DNS names are typically ASCII, so character count approximates byte count
        if (normalized.Length > maxZoneNameLength)
        {
            throw new ArgumentException($"Zone name length ({normalized.Length}) exceeds maximum ({maxZoneNameLength})", nameof(zoneName));
        }

        // Check for empty after normalization
        if (string.IsNullOrEmpty(normalized))
        {
            throw new ArgumentException("Zone name cannot be empty or only dots", nameof(zoneName));
        }

        // RFC 1035: DNS name format validation
        // - Each label: 1-63 characters, alphanumeric and hyphen
        // - Labels separated by dots
        // - Total length: max 253 characters (for FQDN)
        // - Cannot start or end with hyphen in a label
        // - Cannot have consecutive dots

        // Check for consecutive dots
        if (normalized.Contains(".."))
        {
            throw new ArgumentException("Zone name contains consecutive dots", nameof(zoneName));
        }

        // Split into labels
        var labels = normalized.Split('.');
        
        if (labels.Length == 0)
        {
            throw new ArgumentException("Zone name has no labels", nameof(zoneName));
        }

        // Validate each label
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
            {
                throw new ArgumentException("Zone name contains empty label", nameof(zoneName));
            }

            // Label length: 1-63 characters (RFC 1035)
            if (label.Length > 63)
            {
                throw new ArgumentException($"Label '{label}' length ({label.Length}) exceeds maximum (63)", nameof(zoneName));
            }

            // Label must start and end with alphanumeric (cannot start/end with hyphen)
            if (label.StartsWith('-') || label.EndsWith('-'))
            {
                throw new ArgumentException($"Label '{label}' cannot start or end with hyphen", nameof(zoneName));
            }

            // Label characters: alphanumeric and hyphen (RFC 1035)
            // Note: We allow underscore for compatibility, though not strictly RFC 1035
            if (!Regex.IsMatch(label, @"^[a-z0-9_-]+$", RegexOptions.IgnoreCase))
            {
                throw new ArgumentException($"Label '{label}' contains invalid characters (only alphanumeric, hyphen, underscore allowed)", nameof(zoneName));
            }
        }

        // Check total length in bytes (approximate - ASCII characters are 1 byte)
        // For internationalized domain names, this is more complex, but we'll use character count as approximation
        var byteLength = System.Text.Encoding.UTF8.GetByteCount(normalized);
        if (byteLength > 253)
        {
            throw new ArgumentException($"Zone name byte length ({byteLength}) exceeds maximum (253)", nameof(zoneName));
        }
    }

    private static Serilog.Events.LogEventLevel ConvertLogLevel(LogLevel logLevel)
    {
        return logLevel switch
        {
            LogLevel.Trace => Serilog.Events.LogEventLevel.Verbose,
            LogLevel.Debug => Serilog.Events.LogEventLevel.Debug,
            LogLevel.Information => Serilog.Events.LogEventLevel.Information,
            LogLevel.Warning => Serilog.Events.LogEventLevel.Warning,
            LogLevel.Error => Serilog.Events.LogEventLevel.Error,
            LogLevel.Critical => Serilog.Events.LogEventLevel.Fatal,
            LogLevel.None => Serilog.Events.LogEventLevel.Fatal,
            _ => Serilog.Events.LogEventLevel.Information
        };
    }
}

