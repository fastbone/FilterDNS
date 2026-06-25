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
        ConfigurationValidator.Validate(appConfig);

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
        ConfigurationValidator.Validate(appConfig);

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

