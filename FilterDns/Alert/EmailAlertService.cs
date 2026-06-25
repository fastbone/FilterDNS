using System.Net;
using System.Net.Mail;
using FilterDns.Config;
using Microsoft.Extensions.Logging;

namespace FilterDns.Alert;

public class EmailAlertService
{
    private readonly EmailConfig? _emailConfig;
    private readonly ILogger<EmailAlertService> _logger;
    private readonly SemaphoreSlim _sendLock = new(1, 1); // Prevent concurrent sends to avoid rate limiting

    public EmailAlertService(EmailConfig? emailConfig, ILogger<EmailAlertService> logger)
    {
        _emailConfig = emailConfig;
        _logger = logger;
    }

    /// <summary>
    /// Checks if email alerts are enabled and configured.
    /// </summary>
    public bool IsEnabled => _emailConfig != null && 
                              _emailConfig.Enabled && 
                              !string.IsNullOrWhiteSpace(_emailConfig.SmtpServer) &&
                              !string.IsNullOrWhiteSpace(_emailConfig.ToAddress);

    /// <summary>
    /// Sends an alert email for a verification issue.
    /// </summary>
    public async Task SendVerificationAlertAsync(
        string zoneName,
        string slaveIp,
        int slavePort,
        uint expectedSerial,
        uint receivedSerial,
        int expectedRecordCount,
        int receivedRecordCount,
        int recordCountDifference,
        int tolerance,
        List<string> mismatchTypes,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled)
            return;

        var subject = $"[FilterDNS Alert] Slave Verification Mismatch - Zone: {zoneName}";
        var body = $@"A slave verification mismatch has been detected.

Zone: {zoneName}
Slave: {slaveIp}:{slavePort}

Expected Serial: {expectedSerial}
Received Serial: {receivedSerial}

Expected Record Count: {expectedRecordCount}
Received Record Count: {receivedRecordCount}
Record Count Difference: {recordCountDifference}
Tolerance: {tolerance}

Mismatch Types: {string.Join(", ", mismatchTypes)}

This indicates that the slave server may not have synchronized correctly with the master.
Please investigate the slave server configuration and network connectivity.

Timestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC";

        await SendEmailAsync(subject, body, cancellationToken);
    }

    /// <summary>
    /// Sends an alert email for a general error.
    /// </summary>
    public async Task SendErrorAlertAsync(
        string component,
        string operation,
        string errorMessage,
        Exception? exception = null,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled)
            return;

        var subject = $"[FilterDNS Alert] Error in {component}";
        var body = $@"An error has occurred in the FilterDNS system.

Component: {component}
Operation: {operation}
Error Message: {errorMessage}

{(exception != null ? $@"
Exception Type: {exception.GetType().Name}
Exception Details: {exception}

Stack Trace:
{exception.StackTrace}" : "")}

Timestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC";

        await SendEmailAsync(subject, body, cancellationToken);
    }

    /// <summary>
    /// Sends a critical alert email requiring immediate attention.
    /// </summary>
    public async Task SendCriticalAlertAsync(
        string title,
        string message,
        CancellationToken cancellationToken = default)
    {
        if (!IsEnabled)
            return;

        var subject = $"[FilterDNS CRITICAL] {title}";
        var body = $@"CRITICAL ALERT - IMMEDIATE ATTENTION REQUIRED

{message}

This is a critical issue that may require manual intervention to resolve.

Timestamp: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC

--
FilterDNS Alert System";

        await SendEmailAsync(subject, body, cancellationToken);
    }

    /// <summary>
    /// Sends an email using the configured SMTP settings.
    /// </summary>
    private async Task SendEmailAsync(string subject, string body, CancellationToken cancellationToken)
    {
        if (!IsEnabled)
            return;

        await _sendLock.WaitAsync(cancellationToken);
        try
        {
            using var smtpClient = CreateSmtpClient();
            using var mailMessage = new MailMessage
            {
                From = new MailAddress(_emailConfig!.FromAddress, _emailConfig.FromName ?? "FilterDNS"),
                Subject = subject,
                Body = body,
                IsBodyHtml = false
            };

            // Add recipients
            foreach (var recipient in _emailConfig.ToAddress.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                mailMessage.To.Add(recipient);
            }

            // Add CC recipients if configured
            if (!string.IsNullOrWhiteSpace(_emailConfig.CcAddress))
            {
                foreach (var cc in _emailConfig.CcAddress.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    mailMessage.CC.Add(cc);
                }
            }

            // Add BCC recipients if configured
            if (!string.IsNullOrWhiteSpace(_emailConfig.BccAddress))
            {
                foreach (var bcc in _emailConfig.BccAddress.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    mailMessage.Bcc.Add(bcc);
                }
            }

            await smtpClient.SendMailAsync(mailMessage, cancellationToken);
            _logger.LogInformation("Alert email sent successfully to {Recipients}", _emailConfig.ToAddress);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to send alert email. Subject: {Subject}", subject);
            // Don't throw - we don't want email failures to crash the application
        }
        finally
        {
            _sendLock.Release();
        }
    }

    /// <summary>
    /// Creates and configures an SMTP client based on the email configuration.
    /// </summary>
    private SmtpClient CreateSmtpClient()
    {
        var smtpClient = new SmtpClient(_emailConfig!.SmtpServer, _emailConfig.SmtpPort);

        // Configure authentication if provided
        if (!string.IsNullOrWhiteSpace(_emailConfig.Username) && !string.IsNullOrWhiteSpace(_emailConfig.Password))
        {
            smtpClient.Credentials = new NetworkCredential(_emailConfig.Username, _emailConfig.Password);
            smtpClient.UseDefaultCredentials = false;
        }
        else
        {
            // Unauthenticated SMTP (default)
            smtpClient.UseDefaultCredentials = false;
        }

        // Configure encryption/security
        if (_emailConfig.EnableSsl)
        {
            smtpClient.EnableSsl = true;
        }
        else if (_emailConfig.EnableStartTls)
        {
            // Note: .NET's SmtpClient doesn't have explicit StartTLS support,
            // but EnableSsl handles both SSL and StartTLS
            smtpClient.EnableSsl = true;
        }
        else
        {
            // Unencrypted SMTP (default)
            smtpClient.EnableSsl = false;
        }

        // Set timeout
        smtpClient.Timeout = _emailConfig.TimeoutSeconds * 1000; // Convert to milliseconds

        return smtpClient;
    }
}
