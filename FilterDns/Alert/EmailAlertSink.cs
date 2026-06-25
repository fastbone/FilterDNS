using FilterDns.Alert;
using Serilog.Core;
using Serilog.Events;

namespace FilterDns.Alert;

/// <summary>
/// Serilog sink that sends email alerts for Error and Critical level log events.
/// </summary>
public class EmailAlertSink : ILogEventSink
{
    private readonly EmailAlertService _emailAlertService;
    private readonly IFormatProvider? _formatProvider;
    private readonly Dictionary<string, DateTime> _lastEmailSentByKey = new();
    private readonly SemaphoreSlim _rateLimitLock = new(1, 1);
    private const int MinSecondsBetweenEmails = 60; // Rate limit: max one email per minute per error type

    public EmailAlertSink(EmailAlertService emailAlertService, IFormatProvider? formatProvider = null)
    {
        _emailAlertService = emailAlertService;
        _formatProvider = formatProvider;
    }

    public void Emit(LogEvent logEvent)
    {
        // Only send alerts for Error and Critical levels
        if (logEvent.Level < LogEventLevel.Error)
            return;

        // Rate limiting: prevent spam
        if (!ShouldSendEmail(logEvent))
            return;

        // Extract component/operation from log event properties
        var component = ExtractProperty(logEvent, "SourceContext") ?? "Unknown";
        var operation = ExtractProperty(logEvent, "Operation") ?? ExtractProperty(logEvent, "Prefix") ?? "Unknown";
        var errorMessage = logEvent.RenderMessage(_formatProvider);

        // Build exception details if present
        Exception? exception = null;
        if (logEvent.Exception != null)
        {
            exception = logEvent.Exception;
        }

        // Send alert asynchronously (fire and forget)
        _ = Task.Run(async () =>
        {
            try
            {
                await _emailAlertService.SendErrorAlertAsync(
                    component,
                    operation,
                    errorMessage,
                    exception);
            }
            catch
            {
                // Silently ignore errors in the alert sink to prevent infinite loops
            }
        });
    }

    private bool ShouldSendEmail(LogEvent logEvent)
    {
        if (!_emailAlertService.IsEnabled)
            return false;

        // Create a unique key for rate limiting based on component and message template
        var rateLimitKey = $"{ExtractProperty(logEvent, "SourceContext")}_{logEvent.MessageTemplate.Text}";

        _rateLimitLock.Wait();
        try
        {
            var now = DateTime.UtcNow;
            
            if (!_lastEmailSentByKey.TryGetValue(rateLimitKey, out var lastSent))
            {
                // First time seeing this error type - allow it
                _lastEmailSentByKey[rateLimitKey] = now;
                return true;
            }

            var timeSinceLastEmail = (now - lastSent).TotalSeconds;

            if (timeSinceLastEmail >= MinSecondsBetweenEmails)
            {
                _lastEmailSentByKey[rateLimitKey] = now;
                return true;
            }

            return false;
        }
        finally
        {
            _rateLimitLock.Release();
        }
    }

    private string? ExtractProperty(LogEvent logEvent, string propertyName)
    {
        if (logEvent.Properties.TryGetValue(propertyName, out var propertyValue))
        {
            return propertyValue.ToString().Trim('"');
        }
        return null;
    }
}
