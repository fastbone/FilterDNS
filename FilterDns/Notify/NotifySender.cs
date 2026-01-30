using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using FilterDns.Config;
using FilterDns.Dns;
using Microsoft.Extensions.Logging;

namespace FilterDns.Notify;

public class NotifySender
{
    private readonly List<SlaveConfig> _slaves;
    private readonly ILogger<NotifySender> _logger;

    public NotifySender(List<SlaveConfig> slaves, ILogger<NotifySender> logger)
    {
        _slaves = slaves;
        _logger = logger;
    }

    public async Task NotifyAllAsync(string zoneName, CancellationToken cancellationToken = default)
    {
        var tasks = _slaves.Select(slave => NotifySlaveAsync(slave, zoneName, cancellationToken));
        await Task.WhenAll(tasks);
    }

    private async Task NotifySlaveAsync(SlaveConfig slave, string zoneName, CancellationToken cancellationToken)
    {
        UdpClient? udpClient = null;
        try
        {
            // Validate slave configuration
            var ipAddress = slave.GetIpAddress();
            if (ipAddress == null)
            {
                _logger.LogWarning("Skipping notification to invalid slave IP {Ip} for zone {Zone}", slave.Ip, zoneName);
                return;
            }

            var endpoint = new IPEndPoint(ipAddress, slave.Port);
            
            // Create UDP client for sending NOTIFY message
            udpClient = new UdpClient();
            
            // Generate random message ID using cryptographic RNG
            var messageId = (ushort)RandomNumberGenerator.GetInt32(0, 65536);
            
            // Build NOTIFY message
            var notifyMessage = DnsMessageParser.BuildNotify(zoneName, messageId);
            
            _logger.LogDebug("Sending NOTIFY message to slave {Ip}:{Port} for zone {Zone} (message ID: {MessageId})", 
                slave.Ip, slave.Port, zoneName, messageId);
            
            // Send NOTIFY message
            var bytesSent = await udpClient.SendAsync(notifyMessage, notifyMessage.Length, endpoint);
            
            if (bytesSent != notifyMessage.Length)
            {
                _logger.LogWarning("Failed to send complete NOTIFY message to slave {Ip}:{Port} for zone {Zone} (sent {Sent} of {Total} bytes)", 
                    slave.Ip, slave.Port, zoneName, bytesSent, notifyMessage.Length);
                return;
            }
            
            // Wait for response with timeout
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(FilterDns.Constants.NotifyTimeoutSeconds));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);
            
            try
            {
                var response = await udpClient.ReceiveAsync(linkedCts.Token);
                
                // Parse response (use defaults with hardening enabled)
                DnsMessage responseMessage;
                try
                {
                    responseMessage = DnsMessageParser.Parse(response.Buffer, null);
                }
                catch (FormatException ex)
                {
                    _logger.LogWarning("Malformed DNS response from slave {Ip}:{Port} for zone {Zone}: {Error}", 
                        slave.Ip, slave.Port, zoneName, ex.Message);
                    return; // Ignore malformed responses
                }
                
                // Verify it's a response to our NOTIFY
                if (responseMessage.Id == messageId && !responseMessage.IsQuery)
                {
                    if (responseMessage.ResponseCode == DnsResponseCode.NoError)
                    {
                        _logger.LogInformation("Successfully notified slave {Ip}:{Port} for zone {Zone} (received positive response)", 
                            slave.Ip, slave.Port, zoneName);
                    }
                    else
                    {
                        _logger.LogWarning("Slave {Ip}:{Port} responded to NOTIFY for zone {Zone} with error code {ResponseCode}", 
                            slave.Ip, slave.Port, zoneName, responseMessage.ResponseCode);
                    }
                }
                else
                {
                    _logger.LogWarning("Received unexpected response from slave {Ip}:{Port} for zone {Zone} (message ID mismatch or not a response)", 
                        slave.Ip, slave.Port, zoneName);
                }
            }
            catch (OperationCanceledException) when (timeoutCts.Token.IsCancellationRequested)
            {
                _logger.LogWarning("Timeout waiting for NOTIFY response from slave {Ip}:{Port} for zone {Zone}", 
                    slave.Ip, slave.Port, zoneName);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to notify slave {Ip}:{Port} for zone {Zone}", slave.Ip, slave.Port, zoneName);
        }
        finally
        {
            udpClient?.Dispose();
        }
    }
}

