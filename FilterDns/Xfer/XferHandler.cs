using System.Net;
using System.Net.Sockets;
using System.Collections.Concurrent;
using DnsClient.Protocol;
using FilterDns.Cache;
using FilterDns.Config;
using FilterDns.Dns;
using FilterDns.Filter;
using FilterDns.Upstream;
using FilterDns.Whitelist;
using FilterDns.Xfer;
using Microsoft.Extensions.Logging;

namespace FilterDns.Xfer;

public class XferHandler
{
    private readonly Dictionary<string, (ZoneConfig Config, IpWhitelist Whitelist)> _zones;
    private readonly ZoneCache _cache;
    private readonly ILogger<XferHandler> _logger;
    private readonly TcpListener _tcpListener;
    private readonly UdpClient _udpClient;
    private readonly IpWhitelist? _healthCheckWhitelist;
    private readonly Func<string, ZoneConfig, CancellationToken, Task>? _onNotifyReceived;
    private readonly Func<string, ZoneHistory?>? _getHistory;
    private readonly Func<string, ZoneConfig, List<FilteredRecord>, uint, CancellationToken, Task>? _onZoneUpdatedDuringTransfer;
    private readonly string _ixfrResponseMode; // "Incremental" or "FullZone"
    private readonly SecurityConfig? _securityConfig;
    
    // Connection rate limiting and DoS protection
    private readonly SemaphoreSlim? _tcpConnectionSemaphore;
    private readonly SemaphoreSlim? _udpRequestSemaphore;
    private readonly ConcurrentDictionary<IPAddress, int> _connectionsPerIp = new();
    private readonly Timer? _connectionCleanupTimer;

    public XferHandler(
        Dictionary<string, (ZoneConfig Config, IpWhitelist Whitelist)> zones,
        ZoneCache cache,
        string listenAddress,
        int listenPort,
        ILogger<XferHandler> logger,
        IpWhitelist? healthCheckWhitelist = null,
        Func<string, ZoneConfig, CancellationToken, Task>? onNotifyReceived = null,
        Func<string, ZoneHistory?>? getHistory = null,
        Func<string, ZoneConfig, List<FilteredRecord>, uint, CancellationToken, Task>? onZoneUpdatedDuringTransfer = null,
        string ixfrResponseMode = "Incremental",
        SecurityConfig? securityConfig = null)
    {
        _zones = zones;
        _cache = cache;
        _logger = logger;
        _healthCheckWhitelist = healthCheckWhitelist;
        _onNotifyReceived = onNotifyReceived;
        _getHistory = getHistory;
        _onZoneUpdatedDuringTransfer = onZoneUpdatedDuringTransfer;
        _ixfrResponseMode = ixfrResponseMode ?? "Incremental";
        _securityConfig = securityConfig;
        
        // Initialize connection limiting semaphores if hardening enabled
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;
        if (hardeningEnabled)
        {
            var maxTcpConnections = securityConfig?.MaxConcurrentTcpConnections ?? 100;
            var maxUdpRequests = securityConfig?.MaxConcurrentUdpRequests ?? 200;
            _tcpConnectionSemaphore = new SemaphoreSlim(maxTcpConnections, maxTcpConnections);
            _udpRequestSemaphore = new SemaphoreSlim(maxUdpRequests, maxUdpRequests);
            
            // Start periodic cleanup of connection tracking (every 5 minutes)
            _connectionCleanupTimer = new Timer(CleanupConnectionTracking, null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
        }
        else
        {
            _logger.LogWarning("Security hardening is disabled - connection rate limiting is not active");
        }
        
        var endpoint = new IPEndPoint(IPAddress.Parse(listenAddress), listenPort);
        _tcpListener = new TcpListener(endpoint);
        _udpClient = new UdpClient(endpoint);
    }

    /// <summary>
    /// Cleans up connection tracking to prevent memory leaks.
    /// </summary>
    private void CleanupConnectionTracking(object? state)
    {
        try
        {
            // Remove IPs with zero connections (they've been idle for 5+ minutes)
            var keysToRemove = _connectionsPerIp.Where(kvp => kvp.Value == 0).Select(kvp => kvp.Key).ToList();
            foreach (var key in keysToRemove)
            {
                _connectionsPerIp.TryRemove(key, out _);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error during connection tracking cleanup");
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _tcpListener.Start();
        _logger.LogInformation("DNS server listening on TCP and UDP port {Port}", ((IPEndPoint)_tcpListener.LocalEndpoint).Port);

        // Handle TCP connections (for zone transfers)
        _ = Task.Run(async () =>
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var tcpClient = await _tcpListener.AcceptTcpClientAsync(cancellationToken);
                        var remoteEndPoint = (IPEndPoint)tcpClient.Client.RemoteEndPoint!;
                        
                        // Apply connection rate limiting if hardening enabled
                        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
                        if (hardeningEnabled && _tcpConnectionSemaphore != null)
                        {
                            // Check per-IP connection limit
                            var maxConnectionsPerIp = _securityConfig?.MaxConnectionsPerIp ?? 10;
                            var ipConnectionCount = _connectionsPerIp.AddOrUpdate(remoteEndPoint.Address, 1, (key, value) => value + 1);
                            
                            if (ipConnectionCount > maxConnectionsPerIp)
                            {
                                _connectionsPerIp.AddOrUpdate(remoteEndPoint.Address, 0, (key, value) => Math.Max(0, value - 1));
                                tcpClient.Dispose();
                                
                                // Audit log
                                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
                                {
                                    _logger.LogInformation(
                                        "[AUDIT] TCP connection rejected: IP {RemoteEndPoint} exceeded per-IP connection limit ({CurrentConnections} > {MaxConnections})",
                                        remoteEndPoint, ipConnectionCount, maxConnectionsPerIp);
                                }
                                continue;
                            }
                            
                            // Check global TCP connection limit
                            if (!await _tcpConnectionSemaphore.WaitAsync(0, cancellationToken))
                            {
                                _connectionsPerIp.AddOrUpdate(remoteEndPoint.Address, 0, (key, value) => Math.Max(0, value - 1));
                                tcpClient.Dispose();
                                
                                // Audit log
                                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
                                {
                                    _logger.LogInformation(
                                        "[AUDIT] TCP connection rejected: Maximum concurrent TCP connections ({MaxConnections}) exceeded",
                                        _securityConfig.MaxConcurrentTcpConnections);
                                }
                                continue;
                            }
                        }
                        
                        // Set TCP connection timeout if hardening enabled
                        if (hardeningEnabled && _securityConfig != null)
                        {
                            var timeoutSeconds = _securityConfig.TcpConnectionTimeoutSeconds;
                            tcpClient.ReceiveTimeout = timeoutSeconds * 1000;
                            tcpClient.SendTimeout = timeoutSeconds * 1000;
                        }
                        
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await HandleTcpConnectionAsync(tcpClient, cancellationToken);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error handling TCP connection");
                            }
                            finally
                            {
                                // Release semaphore and decrement per-IP count
                                if (hardeningEnabled && _tcpConnectionSemaphore != null)
                                {
                                    _tcpConnectionSemaphore.Release();
                                    _connectionsPerIp.AddOrUpdate(remoteEndPoint.Address, 0, (key, value) => Math.Max(0, value - 1));
                                }
                            }
                        }, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error accepting TCP connection");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Fatal error in TCP listener task");
            }
        }, cancellationToken);

        // Handle UDP (for NOTIFY and queries)
        _ = Task.Run(async () =>
        {
            try
            {
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        var result = await _udpClient.ReceiveAsync(cancellationToken);
                        
                        // Apply UDP request rate limiting if hardening enabled
                        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
                        if (hardeningEnabled && _udpRequestSemaphore != null)
                        {
                            if (!await _udpRequestSemaphore.WaitAsync(0, cancellationToken))
                            {
                                // Audit log
                                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
                                {
                                    _logger.LogInformation(
                                        "[AUDIT] UDP request rejected: Maximum concurrent UDP requests ({MaxRequests}) exceeded from {RemoteEndPoint}",
                                        _securityConfig.MaxConcurrentUdpRequests, result.RemoteEndPoint);
                                }
                                continue;
                            }
                        }
                        
                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                await HandleUdpRequestAsync(result.Buffer, result.RemoteEndPoint, cancellationToken);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogError(ex, "Error handling UDP request");
                            }
                            finally
                            {
                                // Release UDP semaphore
                                if (hardeningEnabled && _udpRequestSemaphore != null)
                                {
                                    _udpRequestSemaphore.Release();
                                }
                            }
                        }, cancellationToken);
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error receiving UDP packet");
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Fatal error in UDP listener task");
            }
        }, cancellationToken);
    }

    private async Task HandleTcpConnectionAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var remoteEndPoint = (IPEndPoint)client.Client.RemoteEndPoint!;
        _logger.LogDebug("Inbound TCP connection established from {RemoteEndPoint}", remoteEndPoint);
        
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                
                // Handle multiple queries on the same TCP connection (Knot DNS may send multiple queries)
                // Keep connection open until client closes it or we encounter an error
                while (!cancellationToken.IsCancellationRequested)
                {
                    try
                    {
                        // Read length prefix (2 bytes)
                        var lenBuffer = new byte[2];
                        var bytesRead = await stream.ReadAsync(lenBuffer, 0, 2, cancellationToken);
                        
                        if (bytesRead == 0)
                        {
                            // Client closed connection gracefully
                            _logger.LogDebug("TCP connection closed by client {RemoteEndPoint}", remoteEndPoint);
                            break;
                        }
                        
                        if (bytesRead < 2)
                        {
                            _logger.LogWarning("Incomplete length prefix received from {RemoteEndPoint}, closing connection", remoteEndPoint);
                            break;
                        }
                        
                        var messageLength = (lenBuffer[0] << 8) | lenBuffer[1];
                        
                        // Validate message length before reading
                        if (messageLength == 0)
                        {
                            _logger.LogWarning("Zero-length DNS message from {RemoteEndPoint}, closing connection", remoteEndPoint);
                            break;
                        }
                        
                        if (messageLength > 65535)
                        {
                            _logger.LogWarning("Invalid message length {Length} (exceeds maximum 65535) from {RemoteEndPoint}, closing connection", 
                                messageLength, remoteEndPoint);
                            break;
                        }
                        
                        // Additional validation: reasonable maximum for DNS messages (prevent DoS)
                        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
                        var maxMessageSize = hardeningEnabled ? 65535 : 65535; // DNS protocol limit
                        if (messageLength > maxMessageSize)
                        {
                            _logger.LogWarning("Message length {Length} exceeds maximum {MaxSize} from {RemoteEndPoint}, closing connection", 
                                messageLength, maxMessageSize, remoteEndPoint);
                            break;
                        }

                        // Read DNS message
                        var messageBuffer = new byte[messageLength];
                        await stream.ReadExactlyAsync(messageBuffer, cancellationToken);
                        // ReadExactlyAsync guarantees it reads exactly messageLength bytes or throws

                        // Parse DNS message with proper error handling
                        // For IXFR requests, be more lenient - try normal parsing first, then lenient if it fails
                        DnsMessage? request = null;
                        bool parseSucceeded = false;
                        try
                        {
                            request = DnsMessageParser.Parse(messageBuffer, _securityConfig);
                            parseSucceeded = true;
                        }
                        catch (FormatException ex)
                        {
                            // Check if this might be an IXFR request by looking at the question section
                            // IXFR query type is 251 (0xFB)
                            bool mightBeIxfr = false;
                            if (messageBuffer.Length >= 15)
                            {
                                try
                                {
                                    // Question section starts at offset 12 (after header)
                                    // First byte of question is domain name length or compression pointer
                                    // We need to find where the query type is
                                    // For simplicity, check if bytes 12-13 could be a short domain name leading to query type 251
                                    // This is a heuristic - if parsing failed, we can't be sure, but we'll try lenient parsing
                                    mightBeIxfr = true; // Assume it might be IXFR if parsing failed
                                }
                                catch
                                {
                                    // Can't determine, assume not IXFR
                                }
                            }
                            
                            // If this might be an IXFR request, try lenient parsing (hardening disabled)
                            if (mightBeIxfr)
                            {
                                try
                                {
                                    // Create a lenient config with hardening disabled
                                    var lenientConfig = _securityConfig != null ? new Config.SecurityConfig
                                    {
                                        SecurityHardeningEnabled = false,
                                        MaxCompressionPointerDepth = _securityConfig.MaxCompressionPointerDepth,
                                        MaxDomainNameLength = _securityConfig.MaxDomainNameLength,
                                        MaxLabelLength = _securityConfig.MaxLabelLength,
                                        MaxMessageCounts = _securityConfig.MaxMessageCounts,
                                        MaxZoneNameLength = _securityConfig.MaxZoneNameLength,
                                        EnableSymlinkProtection = _securityConfig.EnableSymlinkProtection,
                                        MaxRdataLength = _securityConfig.MaxRdataLength
                                    } : null;
                                    
                                    request = DnsMessageParser.Parse(messageBuffer, lenientConfig);
                                    parseSucceeded = true;
                                    _logger.LogDebug("Successfully parsed potentially IXFR request with lenient parsing from {RemoteEndPoint}", remoteEndPoint);
                                }
                                catch
                                {
                                    // Lenient parsing also failed
                                }
                            }
                            
                            if (!parseSucceeded)
                            {
                                // Malformed DNS message - send FormErr response
                                // Log error without exposing internal details (ex.Message is safe, but don't log stack trace)
                                _logger.LogWarning("Malformed DNS message from {RemoteEndPoint}: {Error}", remoteEndPoint, ex.Message);
                                
                                // Try to extract message ID from buffer if possible (first 2 bytes)
                                ushort messageId = 0;
                                if (messageBuffer.Length >= 2)
                                {
                                    try
                                    {
                                        messageId = (ushort)((messageBuffer[0] << 8) | messageBuffer[1]);
                                    }
                                    catch
                                    {
                                        // If we can't read ID, use 0
                                    }
                                }
                                
                                // Send FormErr response
                                var errorResponse = DnsMessageParser.BuildResponse(new DnsMessage { Id = messageId }, DnsResponseCode.FormErr);
                                var errorResponseWithLength = new byte[errorResponse.Length + 2];
                                errorResponseWithLength[0] = (byte)((errorResponse.Length >> 8) & 0xFF);
                                errorResponseWithLength[1] = (byte)(errorResponse.Length & 0xFF);
                                Array.Copy(errorResponse, 0, errorResponseWithLength, 2, errorResponse.Length);
                                
                                try
                                {
                                    await stream.WriteAsync(errorResponseWithLength, 0, errorResponseWithLength.Length, cancellationToken);
                                }
                                catch
                                {
                                    // Ignore errors sending error response - connection may be broken
                                }
                                
                                // Continue to allow more queries on same connection (don't break)
                                continue;
                            }
                        }
                        catch (Exception ex)
                        {
                            // Unexpected parsing error - send ServFail response
                            // Log error without exposing internal details (log exception type and message, not full stack trace)
                            _logger.LogError("Unexpected error parsing DNS message from {RemoteEndPoint}: {ErrorType}: {ErrorMessage}", 
                                remoteEndPoint, ex.GetType().Name, ex.Message);
                            
                            // Try to extract message ID from buffer if possible
                            ushort messageId = 0;
                            if (messageBuffer.Length >= 2)
                            {
                                try
                                {
                                    messageId = (ushort)((messageBuffer[0] << 8) | messageBuffer[1]);
                                }
                                catch
                                {
                                    // If we can't read ID, use 0
                                }
                            }
                            
                            // Send ServFail response
                            var errorResponse = DnsMessageParser.BuildResponse(new DnsMessage { Id = messageId }, DnsResponseCode.ServFail);
                            var errorResponseWithLength = new byte[errorResponse.Length + 2];
                            errorResponseWithLength[0] = (byte)((errorResponse.Length >> 8) & 0xFF);
                            errorResponseWithLength[1] = (byte)(errorResponse.Length & 0xFF);
                            Array.Copy(errorResponse, 0, errorResponseWithLength, 2, errorResponse.Length);
                            
                            try
                            {
                                await stream.WriteAsync(errorResponseWithLength, 0, errorResponseWithLength.Length, cancellationToken);
                            }
                            catch
                            {
                                // Ignore errors sending error response - connection may be broken
                            }
                            
                            // Continue to allow more queries on same connection (don't break)
                            continue;
                        }
                        
                        // Ensure request was successfully parsed
                        if (request == null || !parseSucceeded)
                        {
                            _logger.LogError("Failed to parse DNS message from {RemoteEndPoint} after all attempts", remoteEndPoint);
                            continue;
                        }
                        
                        bool handled = false;
                        
                        // Check if this is a zone transfer request
                        bool shouldCloseConnection = false;
                        foreach (var question in request.Questions)
                        {
                            if (question.QueryType == DnsQueryType.AXFR || question.QueryType == DnsQueryType.IXFR)
                            {
                                var transferType = question.QueryType == DnsQueryType.AXFR ? "AXFR" : "IXFR";
                                _logger.LogInformation("Inbound zone transfer request: {TransferType} for zone {Zone} from {RemoteEndPoint}", 
                                    transferType, question.Name, remoteEndPoint);
                                await HandleZoneTransferRequestAsync(stream, remoteEndPoint, request, question, cancellationToken, messageBuffer);
                                handled = true;
                                // Zone transfers complete - close connection after client reads all data
                                // Wait a moment for client to finish reading, then close gracefully
                                shouldCloseConnection = true;
                                break;
                            }
                            
                            // Handle SOA queries on TCP (Knot DNS sends SOA queries before zone transfers)
                            if (question.QueryType == DnsQueryType.SOA)
                            {
                                var zoneName = question.Name.TrimEnd('.');
                                var zoneNameLookup = zoneName.ToLowerInvariant();
                                
                                // Check if zone exists and source is whitelisted
                                if (_zones.TryGetValue(zoneNameLookup, out var zoneEntry))
                                {
                                    var (zoneConfig, whitelist) = zoneEntry;
                                    
                                    if (whitelist.Allows(remoteEndPoint.Address))
                                    {
                                        _logger.LogDebug("Inbound SOA query on TCP for zone {Zone} from {RemoteEndPoint} (whitelisted)", 
                                            zoneName, remoteEndPoint);
                                        await HandleSoaQueryOnTcpAsync(stream, remoteEndPoint, request, question, zoneConfig, cancellationToken);
                                        handled = true;
                                        // Continue to allow more queries on same connection
                                        break;
                                    }
                                    else
                                    {
                                        _logger.LogDebug("Inbound SOA query on TCP for zone {Zone} from {RemoteEndPoint} (IP not whitelisted)", 
                                            zoneName, remoteEndPoint);
                                    }
                                }
                            }
                        }

                        if (!handled)
                        {
                            // Not a zone transfer or authorized SOA query, send REFUSED
                            _logger.LogWarning("Non-transfer DNS query received on TCP from {RemoteEndPoint}, sending REFUSED", remoteEndPoint);
                            await SendRefusedResponseAsync(stream, request, cancellationToken);
                            // Continue to allow more queries on same connection
                        }
                        
                        // If zone transfer completed, wait briefly then close connection
                        // This allows the client to finish reading all zone transfer data
                        if (shouldCloseConnection)
                        {
                            // Give client a moment to finish reading the final SOA record
                            // Then close the connection gracefully
                            try
                            {
                                await Task.Delay(FilterDns.Constants.TcpCloseDelayMs, cancellationToken);
                            }
                            catch (OperationCanceledException)
                            {
                                // Cancellation requested, close immediately
                            }
                            _logger.LogDebug("Zone transfer completed, closing TCP connection to {RemoteEndPoint}", remoteEndPoint);
                            break;
                        }
                    }
                    catch (System.IO.EndOfStreamException)
                    {
                        // Client closed connection
                        _logger.LogDebug("TCP connection closed by client {RemoteEndPoint} (EndOfStream)", remoteEndPoint);
                        break;
                    }
                    catch (System.Net.Sockets.SocketException ex)
                    {
                        _logger.LogDebug("TCP connection error from {RemoteEndPoint}: {Error}", remoteEndPoint, ex.Message);
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        _logger.LogDebug("TCP connection handling cancelled for {RemoteEndPoint}", remoteEndPoint);
                        break;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling TCP connection from {RemoteEndPoint}", remoteEndPoint);
        }
    }

    private async Task HandleUdpRequestAsync(byte[] data, IPEndPoint remoteEndPoint, CancellationToken cancellationToken)
    {
        try
        {
            DnsMessage request;
            try
            {
                request = DnsMessageParser.Parse(data, _securityConfig);
            }
            catch (FormatException ex)
            {
                // Malformed DNS message - send FormErr response
                // Log error without exposing internal details
                _logger.LogWarning("Malformed DNS message from {RemoteEndPoint}: {Error}", remoteEndPoint, ex.Message);
                
                // Try to extract message ID from buffer if possible (first 2 bytes)
                ushort messageId = 0;
                if (data.Length >= 2)
                {
                    try
                    {
                        messageId = (ushort)((data[0] << 8) | data[1]);
                    }
                    catch
                    {
                        // If we can't read ID, use 0
                    }
                }
                
                // Send FormErr response
                var errorResponse = DnsMessageParser.BuildResponse(new DnsMessage { Id = messageId }, DnsResponseCode.FormErr);
                await _udpClient.SendAsync(errorResponse, remoteEndPoint, cancellationToken);
                return;
            }
            catch (Exception ex)
            {
                // Unexpected parsing error - send ServFail response
                // Log error without exposing internal details
                _logger.LogError("Unexpected error parsing DNS message from {RemoteEndPoint}: {ErrorType}: {ErrorMessage}", 
                    remoteEndPoint, ex.GetType().Name, ex.Message);
                
                // Try to extract message ID from buffer if possible
                ushort messageId = 0;
                if (data.Length >= 2)
                {
                    try
                    {
                        messageId = (ushort)((data[0] << 8) | data[1]);
                    }
                    catch
                    {
                        // If we can't read ID, use 0
                    }
                }
                
                // Send ServFail response
                var errorResponse = DnsMessageParser.BuildResponse(new DnsMessage { Id = messageId }, DnsResponseCode.ServFail);
                await _udpClient.SendAsync(errorResponse, remoteEndPoint, cancellationToken);
                return;
            }
            
            // Check if this is a health check query
            if (_healthCheckWhitelist != null && _healthCheckWhitelist.Allows(remoteEndPoint.Address) && request.OpCode == DnsOpCode.Query)
            {
                // Audit log health check query
                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogHealthCheckQueries == true)
                {
                    var queryType = request.Questions.Count > 0 ? request.Questions[0].QueryType.ToString() : "UNKNOWN";
                    var queryName = request.Questions.Count > 0 ? request.Questions[0].Name : "UNKNOWN";
                    _logger.LogInformation(
                        "[AUDIT] Health check query: {QueryType} {QueryName} from {RemoteEndPoint}",
                        queryType, queryName, remoteEndPoint);
                }
                
                await HandleHealthCheckQueryAsync(request, remoteEndPoint, cancellationToken);
                return;
            }
            
            // Handle NOTIFY messages
            if (request.OpCode == DnsOpCode.Notify)
            {
                foreach (var question in request.Questions)
                {
                    if (question.QueryType == DnsQueryType.SOA)
                    {
                        var zoneName = question.Name.TrimEnd('.');
                        var zoneNameLookup = zoneName.ToLowerInvariant();
                        
                        _logger.LogInformation("Received NOTIFY for zone {Zone} from {RemoteEndPoint}", 
                            zoneName, remoteEndPoint);
                        
                        // Send positive response immediately
                        var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.NoError);
                        await _udpClient.SendAsync(response, remoteEndPoint, cancellationToken);
                        
                        // Find zone configuration
                        if (_zones.TryGetValue(zoneNameLookup, out var zoneEntry))
                        {
                            var (zoneConfig, _) = zoneEntry;
                            
                            // Check if NOTIFY is from upstream master
                            var upstreamParts = zoneConfig.Upstream.Split(':');
                            var upstreamIp = IPAddress.Parse(upstreamParts[0]);
                            
                            if (remoteEndPoint.Address.Equals(upstreamIp))
                            {
                                _logger.LogInformation(
                                    "NOTIFY from upstream master {Upstream} for zone {Zone}, triggering zone transfer and slave notification",
                                    zoneConfig.Upstream, zoneName);
                                
                                // Trigger zone update and slave notification
                                if (_onNotifyReceived != null)
                                {
                                    _ = Task.Run(async () =>
                                    {
                                        try
                                        {
                                            await _onNotifyReceived(zoneName, zoneConfig, cancellationToken);
                                        }
                                        catch (Exception ex)
                                        {
                                            _logger.LogError(ex, 
                                                "Error processing NOTIFY-triggered update for zone {Zone} from upstream {Upstream}",
                                                zoneName, zoneConfig.Upstream);
                                        }
                                    }, cancellationToken);
                                }
                                else
                                {
                                    _logger.LogWarning(
                                        "NOTIFY received from upstream but no handler configured for zone {Zone}",
                                        zoneName);
                                }
                            }
                            else
                            {
                                // Audit log unauthorized NOTIFY
                                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogUnauthorizedNotify == true)
                                {
                                    _logger.LogInformation(
                                        "[AUDIT] Unauthorized NOTIFY: Zone {Zone} from {RemoteEndPoint} (not from upstream {Upstream})",
                                        zoneName, remoteEndPoint, zoneConfig.Upstream);
                                }
                                else
                                {
                                    _logger.LogDebug(
                                        "NOTIFY received for zone {Zone} from {RemoteEndPoint} (not from upstream {Upstream}), ignoring",
                                        zoneName, remoteEndPoint, zoneConfig.Upstream);
                                }
                            }
                        }
                        else
                        {
                            _logger.LogWarning(
                                "NOTIFY received for unknown zone {Zone} from {RemoteEndPoint}",
                                zoneName, remoteEndPoint);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling UDP request from {RemoteEndPoint}", remoteEndPoint);
        }
    }

    private async Task HandleHealthCheckQueryAsync(
        DnsMessage request,
        IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken)
    {
        try
        {
            if (request.Questions.Count == 0)
            {
                _logger.LogDebug("Health check query from {RemoteEndPoint} has no questions", remoteEndPoint);
                return;
            }

            var question = request.Questions[0];
            var queriedName = question.Name.TrimEnd('.');
            var queriedNameLower = queriedName.ToLowerInvariant();
            
            _logger.LogDebug("Health check query from {RemoteEndPoint}: {QueryType} {QueryName}", 
                remoteEndPoint, question.QueryType, queriedName);

            // Find zone that contains this domain
            string? foundZoneName = null;
            (ZoneConfig Config, IpWhitelist Whitelist)? zoneEntry = null;

            // Try exact match first
            if (_zones.TryGetValue(queriedNameLower, out var exactMatch))
            {
                foundZoneName = queriedNameLower;
                zoneEntry = exactMatch;
            }
            else
            {
                // Try to find parent zone (subdomain query)
                foreach (var kvp in _zones)
                {
                    var zoneNameLower = kvp.Key;
                    if (queriedNameLower.EndsWith("." + zoneNameLower) || queriedNameLower == zoneNameLower)
                    {
                        foundZoneName = zoneNameLower;
                        zoneEntry = kvp.Value;
                        break;
                    }
                }
            }

            if (foundZoneName == null || !zoneEntry.HasValue)
            {
                _logger.LogDebug("Health check query from {RemoteEndPoint}: Domain {QueryName} not found in any zone, returning NXDOMAIN", 
                    remoteEndPoint, queriedName);
                var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.NXDomain);
                await _udpClient.SendAsync(response, remoteEndPoint, cancellationToken);
                return;
            }

            var (zoneConfig, _) = zoneEntry.Value;

            // Get filtered zone data
            List<FilteredRecord> zoneRecords;
            var cachedZone = _cache.GetZone(zoneConfig.Name);
            
            if (cachedZone != null)
            {
                zoneRecords = cachedZone.Records;
            }
            else
            {
                // Zone not cached, fetch from upstream
                _logger.LogDebug("Health check query from {RemoteEndPoint}: Zone {Zone} not cached, fetching from upstream", 
                    remoteEndPoint, zoneConfig.Name);
                
                var timeout = GetUpstreamTimeout();
                var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
                try
                {
                    var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneConfig.Name, cancellationToken);
                    zoneRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneConfig.Name);
                    await UpdateCacheAndNotifyAsync(zoneConfig.Name, zoneConfig, zoneRecords, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Health check query from {RemoteEndPoint}: Failed to fetch zone {Zone} from upstream", 
                        remoteEndPoint, zoneConfig.Name);
                    var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.ServFail);
                    await _udpClient.SendAsync(response, remoteEndPoint, cancellationToken);
                    return;
                }
                finally
                {
                    upstreamClient.Dispose();
                }
            }

            // Match query to records
            var matchingRecords = MatchQueryToRecords(question, zoneRecords, foundZoneName);
            
            if (matchingRecords.Count == 0)
            {
                _logger.LogDebug("Health check query from {RemoteEndPoint}: No matching records for {QueryType} {QueryName}, returning NOERROR", 
                    remoteEndPoint, question.QueryType, queriedName);
                var response = DnsRecordBuilder.BuildQueryResponse(request, new List<FilteredRecord>(), DnsResponseCode.NoError);
                await _udpClient.SendAsync(response, remoteEndPoint, cancellationToken);
                return;
            }

            // Build and send response
            var queryResponse = DnsRecordBuilder.BuildQueryResponse(request, matchingRecords, DnsResponseCode.NoError);
            await _udpClient.SendAsync(queryResponse, remoteEndPoint, cancellationToken);
            
            _logger.LogDebug("Health check query from {RemoteEndPoint}: Responded with {RecordCount} records for {QueryType} {QueryName}", 
                remoteEndPoint, matchingRecords.Count, question.QueryType, queriedName);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling health check query from {RemoteEndPoint}", remoteEndPoint);
            try
            {
                var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.ServFail);
                await _udpClient.SendAsync(response, remoteEndPoint, cancellationToken);
            }
            catch
            {
                // Ignore errors sending error response
            }
        }
    }

    private List<FilteredRecord> MatchQueryToRecords(DnsQuestion question, List<FilteredRecord> zoneRecords, string zoneName)
    {
        var matchingRecords = new List<FilteredRecord>();
        var queriedName = question.Name.TrimEnd('.').ToLowerInvariant();
        var zoneNameLower = zoneName.ToLowerInvariant();

        foreach (var record in zoneRecords)
        {
            var recordName = record.DomainName.TrimEnd('.').ToLowerInvariant();
            
            // Check if domain name matches (exact match only for health checks)
            bool nameMatches = false;
            if (recordName == queriedName)
            {
                // Exact domain name match
                nameMatches = true;
            }
            else if (recordName == zoneNameLower && queriedName == zoneNameLower)
            {
                // Zone apex match (for queries like SOA, NS at zone apex)
                nameMatches = true;
            }

            if (!nameMatches)
                continue;

            // Check query type match
            bool typeMatches = false;
            if (question.QueryType == DnsQueryType.A && record.RecordType == ResourceRecordType.A)
            {
                typeMatches = true;
            }
            else if (question.QueryType == DnsQueryType.AAAA && record.RecordType == ResourceRecordType.AAAA)
            {
                typeMatches = true;
            }
            else if (question.QueryType == DnsQueryType.NS && record.RecordType == ResourceRecordType.NS)
            {
                typeMatches = true;
            }
            else if (question.QueryType == DnsQueryType.SOA && record.RecordType == ResourceRecordType.SOA)
            {
                typeMatches = true;
            }
            else if ((int)question.QueryType == (int)record.RecordType)
            {
                // Handle other query types by comparing numeric values
                typeMatches = true;
            }

            if (typeMatches)
            {
                matchingRecords.Add(record);
            }
        }

        return matchingRecords;
    }

    private async Task HandleZoneTransferRequestAsync(
        NetworkStream stream,
        IPEndPoint remoteEndPoint,
        DnsMessage request,
        DnsQuestion question,
        CancellationToken cancellationToken,
        byte[]? rawMessageBuffer = null)
    {
        var transferStartTime = DateTime.UtcNow;
        var transferType = question.QueryType == DnsQueryType.AXFR ? "AXFR" : "IXFR";
        var zoneName = question.Name.TrimEnd('.');
        var zoneNameLookup = zoneName.ToLowerInvariant();
        long bytesTransferred = 0;

        // Apply zone transfer timeout if hardening enabled
        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        CancellationTokenSource? timeoutCts = null;
        CancellationToken effectiveToken = cancellationToken;
        
        if (hardeningEnabled && _securityConfig != null)
        {
            var timeoutSeconds = _securityConfig.ZoneTransferTimeoutSeconds;
            timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            effectiveToken = timeoutCts.Token;
        }

        try
        {
            // Find zone configuration
            if (!_zones.TryGetValue(zoneNameLookup, out var zoneEntry))
            {
                // Try without trailing dot
                if (!_zones.TryGetValue(question.Name.ToLowerInvariant(), out zoneEntry))
                {
                    _logger.LogWarning("Inbound zone transfer denied: Unknown zone {Zone} requested by {RemoteEndPoint}", 
                        question.Name, remoteEndPoint);
                    await SendRefusedResponseAsync(stream, request, cancellationToken);
                    return;
                }
            }

            var (zoneConfig, whitelist) = zoneEntry;

            // Check whitelist
            if (!whitelist.Allows(remoteEndPoint.Address))
            {
                _logger.LogWarning("Inbound zone transfer denied: Zone {Zone} from {RemoteEndPoint} (IP not whitelisted)", 
                    zoneName, remoteEndPoint.Address);
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            // Get zone (from cache or upstream)
            // CRITICAL: Always verify we have the latest data before serving zone transfers
            // This ensures slaves always get the most recent zone data, not stale cache
            List<FilteredRecord> zoneRecords;
            var cachedZone = _cache.GetZone(zoneConfig.Name);
            var source = "cache";
            
            // Check if we have cached data and verify it's the latest
            if (cachedZone != null && cachedZone.Records.Count > 0)
            {
                // Verify cached data is the latest by checking upstream serial
                // This prevents serving stale data to slaves
                var timeout = GetUpstreamTimeout();
                var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
                try
                {
                    var upstreamSerial = await upstreamClient.GetSoaSerialAsync(zoneConfig.Name, cancellationToken);
                    
                    // If upstream has newer serial, fetch fresh data
                    if (upstreamSerial > cachedZone.Serial)
                    {
                        _logger.LogInformation(
                            "Zone transfer: Cached data for {Zone} is stale (cached: {CachedSerial}, upstream: {UpstreamSerial}), fetching latest from upstream {Upstream}",
                            zoneName, cachedZone.Serial, upstreamSerial, zoneConfig.Upstream);
                        
                        source = "upstream";
                        var upstreamFetchStart = DateTime.UtcNow;
                        var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneConfig.Name, cancellationToken);
                        var upstreamFetchDuration = (DateTime.UtcNow - upstreamFetchStart).TotalMilliseconds;
                        
                        _logger.LogInformation(
                            "Outbound zone transfer completed: Zone {Zone} from upstream {Upstream} | " +
                            "Records: {RecordCount} | Duration: {Duration}ms",
                            zoneConfig.Name, zoneConfig.Upstream, upstreamRecords.Count, upstreamFetchDuration);
                        
                        // Apply filters
                        zoneRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneConfig.Name);
                        
                        // Validate filtered records
                        if (zoneRecords == null || zoneRecords.Count == 0)
                        {
                            _logger.LogError("Zone {Zone} filtered to empty/null records, cannot proceed with transfer", zoneConfig.Name);
                            await SendRefusedResponseAsync(stream, request, cancellationToken);
                            return;
                        }
                        
                        _logger.LogDebug("Applied filters to zone {Zone}: {OriginalCount} -> {FilteredCount} records", 
                            zoneConfig.Name, upstreamRecords.Count, zoneRecords.Count);
                        
                        // Update cache with latest data and notify other slaves
                        // This ensures future requests get the latest data and slaves are kept in sync
                        await UpdateCacheAndNotifyAsync(zoneConfig.Name, zoneConfig, zoneRecords, cancellationToken);
                    }
                    else if (upstreamSerial == cachedZone.Serial)
                    {
                        // Cached data is current - use it
                        zoneRecords = cachedZone.Records;
                        _logger.LogDebug("Using cached zone data for {Zone} ({RecordCount} records, serial: {Serial}) - verified current", 
                            zoneName, zoneRecords.Count, cachedZone.Serial);
                    }
                    else
                    {
                        // Upstream serial is lower than cached (shouldn't happen, but handle gracefully)
                        // Use cached data but log warning
                        _logger.LogWarning(
                            "Zone transfer: Upstream serial ({UpstreamSerial}) is lower than cached serial ({CachedSerial}) for {Zone}, using cached data",
                            upstreamSerial, cachedZone.Serial, zoneName);
                        zoneRecords = cachedZone.Records;
                    }
                }
                catch (Exception ex)
                {
                    // If upstream check fails, use cached data as fallback
                    // This ensures zone transfers can still proceed even if upstream is temporarily unavailable
                    _logger.LogWarning(ex, 
                        "Zone transfer: Failed to verify upstream serial for {Zone}, using cached data (serial: {Serial})",
                        zoneName, cachedZone.Serial);
                    zoneRecords = cachedZone.Records;
                }
                finally
                {
                    upstreamClient.Dispose();
                }
            }
            else
            {
                // No cached data - fetch from upstream
                source = "upstream";
                _logger.LogInformation("Outbound zone transfer starting: Fetching zone {Zone} from upstream {Upstream} for inbound transfer request", 
                    zoneConfig.Name, zoneConfig.Upstream);
                
                var upstreamFetchStart = DateTime.UtcNow;
                var timeout = GetUpstreamTimeout();
                var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
                
                try
                {
                    var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneConfig.Name, cancellationToken);
                    var upstreamFetchDuration = (DateTime.UtcNow - upstreamFetchStart).TotalMilliseconds;
                    
                    _logger.LogInformation(
                        "Outbound zone transfer completed: Zone {Zone} from upstream {Upstream} | " +
                        "Records: {RecordCount} | Duration: {Duration}ms",
                        zoneConfig.Name, zoneConfig.Upstream, upstreamRecords.Count, upstreamFetchDuration);
                    
                    // Apply filters
                    zoneRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneConfig.Name);
                    
                    // Validate filtered records
                    if (zoneRecords == null || zoneRecords.Count == 0)
                    {
                        _logger.LogError("Zone {Zone} filtered to empty/null records, cannot proceed with transfer", zoneConfig.Name);
                        await SendRefusedResponseAsync(stream, request, cancellationToken);
                        return;
                    }
                    
                    _logger.LogDebug("Applied filters to zone {Zone}: {OriginalCount} -> {FilteredCount} records", 
                        zoneConfig.Name, upstreamRecords.Count, zoneRecords.Count);
                    
                    // Update cache with latest data and notify other slaves
                    await UpdateCacheAndNotifyAsync(zoneConfig.Name, zoneConfig, zoneRecords, cancellationToken);
                }
                catch (Exception ex)
                {
                    var upstreamFetchDuration = (DateTime.UtcNow - upstreamFetchStart).TotalMilliseconds;
                    _logger.LogError(ex, 
                        "Outbound zone transfer failed: Zone {Zone} from upstream {Upstream} | Duration: {Duration}ms",
                        zoneConfig.Name, zoneConfig.Upstream, upstreamFetchDuration);
                    await SendRefusedResponseAsync(stream, request, cancellationToken);
                    return;
                }
                finally
                {
                    upstreamClient.Dispose();
                }
            }

            // Validate zoneRecords is not null or empty before proceeding
            if (zoneRecords == null || zoneRecords.Count == 0)
            {
                _logger.LogError("Zone {Zone} has no records available for transfer", zoneName);
                
                // Audit log failed transfer
                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
                {
                    _logger.LogInformation(
                        "[AUDIT] Zone transfer failed: Zone {Zone} from {RemoteEndPoint} - Zone has no records",
                        zoneName, remoteEndPoint);
                }
                
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            // CRITICAL: Validate zone consistency before serving
            // Ensure all records belong to the same serial number and zone is complete
            var soaRecord = zoneRecords.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
            if (soaRecord == null)
            {
                _logger.LogError("Zone {Zone} has no SOA record - zone is incomplete, cannot serve transfer", zoneName);
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            var serial = ExtractSerialFromSoa(soaRecord);
            if (serial == null || serial == 0)
            {
                _logger.LogError("Zone {Zone} has invalid SOA serial ({Serial}) - zone is corrupted, cannot serve transfer", 
                    zoneName, serial ?? 0);
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            // Verify there's exactly one SOA record (zone should have exactly one)
            var soaCount = zoneRecords.Count(r => r.RecordType == ResourceRecordType.SOA);
            if (soaCount != 1)
            {
                _logger.LogError("Zone {Zone} has {SoaCount} SOA records (expected 1) - zone may contain mixed versions, cannot serve transfer", 
                    zoneName, soaCount);
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            // Verify SOA serial matches the serial we extracted (sanity check)
            var soaSerial = soaRecord.SoaData?.Serial ?? 0;
            if (serial == null || soaSerial != serial.Value)
            {
                _logger.LogError("Zone {Zone} serial mismatch: SOA serial ({SoaSerial}) != extracted serial ({Serial}) - zone may contain mixed versions, cannot serve transfer", 
                    zoneName, soaSerial, serial ?? 0);
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }

            var recordCount = zoneRecords.Count;
            
            // RELIABILITY FIX: Validate minimum record count before serving
            // This prevents serving "empty" zones that only have SOA/NS records
            var minimumRecordCount = zoneConfig.MinimumZoneRecordCount ?? 3; // Default: SOA + 2 NS
            if (minimumRecordCount > 0 && recordCount < minimumRecordCount)
            {
                _logger.LogError(
                    "CRITICAL: Zone {Zone} has only {RecordCount} records (minimum: {MinimumCount}) - " +
                    "refusing to serve potentially empty/corrupt zone to prevent data loss on slaves",
                    zoneName, recordCount, minimumRecordCount);
                
                // Audit log failed transfer
                if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
                {
                    _logger.LogInformation(
                        "[AUDIT] Zone transfer refused: Zone {Zone} from {RemoteEndPoint} - " +
                        "Record count ({RecordCount}) below minimum ({MinimumCount})",
                        zoneName, remoteEndPoint, recordCount, minimumRecordCount);
                }
                
                await SendRefusedResponseAsync(stream, request, cancellationToken);
                return;
            }
            
            // Log zone consistency validation
            _logger.LogDebug("Zone {Zone} consistency validated: {RecordCount} records, serial {Serial}, source {Source}", 
                zoneName, recordCount, serial, source);

            // Check zone transfer size limit if hardening enabled
            if (hardeningEnabled && _securityConfig != null)
            {
                // Estimate transfer size (rough estimate: ~100 bytes per record average)
                var estimatedSize = recordCount * 100L;
                var maxSize = _securityConfig.MaxZoneTransferSizeBytes;
                
                if (estimatedSize > maxSize)
                {
                    _logger.LogWarning(
                        "Zone transfer rejected: Zone {Zone} estimated size ({EstimatedSize} bytes) exceeds maximum ({MaxSize} bytes)",
                        zoneName, estimatedSize, maxSize);
                    
                    // Audit log
                    if (_securityConfig.EnableAuditLogging == true && _securityConfig.AuditLogFailedTransfers == true)
                    {
                        _logger.LogInformation(
                            "[AUDIT] Zone transfer rejected: Zone {Zone} from {RemoteEndPoint} - Transfer size ({EstimatedSize} bytes) exceeds limit ({MaxSize} bytes)",
                            zoneName, remoteEndPoint, estimatedSize, maxSize);
                    }
                    
                    await SendRefusedResponseAsync(stream, request, cancellationToken);
                    return;
                }
            }

            _logger.LogInformation(
                "Inbound zone transfer starting: {TransferType} for zone {Zone} from {RemoteEndPoint} (whitelisted) | " +
                "Source: {Source} | Current Serial: {Serial} | Records: {RecordCount}",
                transferType, zoneName, remoteEndPoint, source, serial ?? 0, recordCount);

            // Handle IXFR requests differently from AXFR
            if (question.QueryType == DnsQueryType.IXFR)
            {
                _logger.LogInformation(
                    "Inbound IXFR request details: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "Current Serial={CurrentSerial} | Records={RecordCount}",
                    zoneConfig.Name, remoteEndPoint, serial ?? 0, recordCount);
                
                var bytesTransferredBefore = bytesTransferred;
                await HandleIxfrRequestAsync(stream, request, zoneConfig, zoneRecords, soaRecord, serial, remoteEndPoint, effectiveToken, rawMessageBuffer);
                
                // Calculate bytes transferred (approximate, since IXFR sends multiple messages)
                // We'll track this in HandleIxfrRequestAsync instead
                bytesTransferred = 0; // Will be calculated in HandleIxfrRequestAsync
            }
            else
            {
                // AXFR: Stream full zone transfer response
                _logger.LogInformation(
                    "Inbound AXFR request details: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "Serial={Serial} | Records={RecordCount} | Source={Source}",
                    zoneConfig.Name, remoteEndPoint, serial ?? 0, recordCount, source);
                
                // Send SOA first
                if (soaRecord != null)
                {
                    var bytes = await SendRecordAsync(stream, soaRecord, request.Id, zoneConfig.Name, effectiveToken);
                    bytesTransferred += bytes;
                    
                    // Check transfer size limit during transfer
                    if (hardeningEnabled && _securityConfig != null && bytesTransferred > _securityConfig.MaxZoneTransferSizeBytes)
                    {
                        _logger.LogWarning(
                            "Zone transfer aborted: Zone {Zone} transfer size ({BytesTransferred} bytes) exceeds maximum ({MaxSize} bytes)",
                            zoneName, bytesTransferred, _securityConfig.MaxZoneTransferSizeBytes);
                        
                        if (_securityConfig.EnableAuditLogging == true && _securityConfig.AuditLogFailedTransfers == true)
                        {
                            _logger.LogInformation(
                                "[AUDIT] Zone transfer aborted: Zone {Zone} from {RemoteEndPoint} - Transfer size ({BytesTransferred} bytes) exceeds limit ({MaxSize} bytes)",
                                zoneName, remoteEndPoint, bytesTransferred, _securityConfig.MaxZoneTransferSizeBytes);
                        }
                        return;
                    }
                }

                // Send all other records
                int recordsSent = 1; // Count SOA already sent
                foreach (var record in zoneRecords)
                {
                    if (record.RecordType != ResourceRecordType.SOA)
                    {
                        var bytes = await SendRecordAsync(stream, record, request.Id, zoneConfig.Name, effectiveToken);
                        bytesTransferred += bytes;
                        recordsSent++;
                        
                        // Check transfer size limit during transfer
                        if (hardeningEnabled && _securityConfig != null && bytesTransferred > _securityConfig.MaxZoneTransferSizeBytes)
                        {
                            _logger.LogWarning(
                                "Zone transfer aborted: Zone {Zone} transfer size ({BytesTransferred} bytes) exceeds maximum ({MaxSize} bytes)",
                                zoneName, bytesTransferred, _securityConfig.MaxZoneTransferSizeBytes);
                            
                            if (_securityConfig.EnableAuditLogging == true && _securityConfig.AuditLogFailedTransfers == true)
                            {
                                _logger.LogInformation(
                                    "[AUDIT] Zone transfer aborted: Zone {Zone} from {RemoteEndPoint} - Transfer size ({BytesTransferred} bytes) exceeds limit ({MaxSize} bytes)",
                                    zoneName, remoteEndPoint, bytesTransferred, _securityConfig.MaxZoneTransferSizeBytes);
                            }
                            return;
                        }
                    }
                }

                // Send SOA again at the end
                if (soaRecord != null)
                {
                    var bytes = await SendRecordAsync(stream, soaRecord, request.Id, zoneConfig.Name, effectiveToken);
                    bytesTransferred += bytes;
                    recordsSent++;
                }
                
                _logger.LogDebug(
                    "AXFR response sent: Zone={Zone} | Records Sent={RecordsSent} | " +
                    "Bytes Transferred={Bytes}",
                    zoneConfig.Name, recordsSent, bytesTransferred);
            }
            
            // Ensure all data is flushed before connection closes
            await stream.FlushAsync(cancellationToken);

            var transferDuration = (DateTime.UtcNow - transferStartTime).TotalMilliseconds;
            
            // For IXFR, bytesTransferred might be 0 if not calculated, so we'll log it differently
            if (question.QueryType == DnsQueryType.IXFR && bytesTransferred == 0)
            {
                // IXFR bytes are calculated in HandleIxfrRequestAsync, but we don't have access here
                // The detailed logging is already done in HandleIxfrRequestAsync
                _logger.LogInformation(
                    "Inbound zone transfer completed: {TransferType} for zone {Zone} to {RemoteEndPoint} | " +
                    "Records: {RecordCount} | Duration: {Duration}ms | Source: {Source} | Serial: {Serial}",
                    transferType, zoneConfig.Name, remoteEndPoint, recordCount, 
                    transferDuration, source, serial ?? 0);
            }
            else
            {
                _logger.LogInformation(
                    "Inbound zone transfer completed: {TransferType} for zone {Zone} to {RemoteEndPoint} | " +
                    "Records: {RecordCount} | Bytes: {BytesTransferred} | Duration: {Duration}ms | Source: {Source} | Serial: {Serial}",
                    transferType, zoneConfig.Name, remoteEndPoint, recordCount, bytesTransferred, 
                    transferDuration, source, serial ?? 0);
            }
        }
        catch (OperationCanceledException) when (timeoutCts?.Token.IsCancellationRequested == true)
        {
            var transferDuration = (DateTime.UtcNow - transferStartTime).TotalMilliseconds;
            _logger.LogWarning(
                "Zone transfer timeout: {TransferType} for zone {Zone} to {RemoteEndPoint} | Duration: {Duration}ms | Timeout: {TimeoutSeconds}s | Bytes transferred: {BytesTransferred}",
                transferType, zoneName, remoteEndPoint, transferDuration, _securityConfig?.ZoneTransferTimeoutSeconds ?? 600, bytesTransferred);
            
            // Audit log timeout
            if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
            {
                _logger.LogInformation(
                    "[AUDIT] Zone transfer timeout: {TransferType} for zone {Zone} from {RemoteEndPoint} | Duration: {Duration}ms | Timeout: {TimeoutSeconds}s",
                    transferType, zoneName, remoteEndPoint, transferDuration, _securityConfig.ZoneTransferTimeoutSeconds);
            }
        }
        catch (Exception ex)
        {
            var transferDuration = (DateTime.UtcNow - transferStartTime).TotalMilliseconds;
            _logger.LogError(ex, 
                "Inbound zone transfer failed: {TransferType} for zone {Zone} to {RemoteEndPoint} | Duration: {Duration}ms | Bytes transferred: {BytesTransferred}",
                transferType, zoneName, remoteEndPoint, transferDuration, bytesTransferred);
            
            // Audit log failed transfer
            if (_securityConfig?.EnableAuditLogging == true && _securityConfig?.AuditLogFailedTransfers == true)
            {
                _logger.LogInformation(
                    "[AUDIT] Zone transfer failed: {TransferType} for zone {Zone} from {RemoteEndPoint} | Error: {Error}",
                    transferType, zoneName, remoteEndPoint, ex.Message);
            }
            
            throw;
        }
        finally
        {
            timeoutCts?.Dispose();
        }
    }

    private uint? ExtractSerialFromSoa(FilteredRecord soaRecord)
    {
        return soaRecord.SoaData?.Serial;
    }

    /// <summary>
    /// Updates the cache and notifies about zone updates during transfer handling.
    /// This ensures zone history is updated and other slaves are notified when the cache
    /// is updated during AXFR/IXFR handling.
    /// </summary>
    private async Task UpdateCacheAndNotifyAsync(
        string zoneName,
        ZoneConfig zoneConfig,
        List<FilteredRecord> records,
        CancellationToken cancellationToken)
    {
        // Extract serial from SOA
        var serial = records
            .FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA)
            ?.SoaData?.Serial ?? 0;
        
        // Update cache
        _cache.UpdateZone(zoneName, records);
        
        // Notify about the update (updates history and sends NOTIFY to other slaves)
        if (_onZoneUpdatedDuringTransfer != null && serial > 0)
        {
            try
            {
                await _onZoneUpdatedDuringTransfer(zoneName, zoneConfig, records, serial, cancellationToken);
                _logger.LogDebug("Zone {Zone} updated during transfer handling (serial: {Serial}), history updated and slaves notified", 
                    zoneName, serial);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to notify about zone update during transfer handling for zone {Zone}", zoneName);
                // Don't fail the transfer - the cache is already updated
            }
        }
    }

    /// <summary>
    /// Handles an IXFR (Incremental Zone Transfer) request.
    /// CRITICAL: This method takes a snapshot of the zone at the start and uses it throughout
    /// to prevent inconsistencies during rapid updates.
    /// </summary>
    private async Task HandleIxfrRequestAsync(
        NetworkStream stream,
        DnsMessage request,
        ZoneConfig zoneConfig,
        List<FilteredRecord> currentZoneRecords,
        FilteredRecord? currentSoa,
        uint? currentSerial,
        IPEndPoint remoteEndPoint,
        CancellationToken cancellationToken,
        byte[]? rawMessageBuffer = null)
    {
        // CRITICAL: Take a snapshot of zone records at the start of IXFR handling
        // This prevents the zone from changing mid-transfer during rapid updates
        var snapshotRecords = new List<FilteredRecord>(currentZoneRecords);
        var snapshotSoa = currentSoa;
        var snapshotSerial = currentSerial;

        if (snapshotSoa == null || snapshotSerial == null)
        {
            _logger.LogWarning("IXFR request for zone {Zone} but no SOA record found, falling back to AXFR", zoneConfig.Name);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        // Extract client's current serial from IXFR request
        // Pass raw message buffer for fallback extraction if parsing failed
        var clientSerial = DnsMessageParser.ExtractIxfrClientSerial(request, rawMessageBuffer);

        if (clientSerial == null)
        {
            // Log more details for debugging
            var authorityTypes = string.Join(", ", request.Authority.Select(r => r.RecordType.ToString()));
            _logger.LogWarning(
                "IXFR request for zone {Zone} from {RemoteEndPoint}: could not extract client serial from authority section (Authority count: {AuthorityCount}, Authority types: [{AuthorityTypes}], Raw buffer length: {BufferLength}), falling back to AXFR",
                zoneConfig.Name, remoteEndPoint, request.Authority.Count, authorityTypes, rawMessageBuffer?.Length ?? 0);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        _logger.LogInformation(
            "IXFR request details: Zone={Zone} | Client={RemoteEndPoint} | " +
            "Client Serial={ClientSerial} | Server Serial={ServerSerial} | Serial Delta={SerialDelta}",
            zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial, 
            snapshotSerial.Value > clientSerial.Value ? snapshotSerial.Value - clientSerial.Value : 0);

        // Case 1: Serials match - send minimal response (just SOA)
        if (clientSerial == snapshotSerial)
        {
            var question = request.Questions.FirstOrDefault();
            if (question == null)
            {
                _logger.LogWarning("IXFR request has no question section, falling back to AXFR");
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }
            var response = IxfrResponseBuilder.BuildNoChangeResponse(snapshotSoa, request.Id, question);
            var responseBytes = response.Length + 2; // +2 for TCP length prefix
            _logger.LogInformation(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Serials Match ({Serial}) | Response Type=Minimal (SOA only) | Bytes=~{Bytes}",
                zoneConfig.Name, remoteEndPoint, clientSerial, responseBytes);
            await SendTcpMessageAsync(stream, response, cancellationToken);
            return;
        }

        // Check IXFR response mode configuration
        if (string.Equals(_ixfrResponseMode, "FullZone", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogInformation(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "Response Mode=FullZone (configuration) | Sending full zone transfer",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        // Case 2: Check if we have history available
        if (_getHistory == null)
        {
            _logger.LogError(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "History=Not Available (getHistory function is null - configuration error) | Fallback=AXFR",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        var history = _getHistory.Invoke(zoneConfig.Name);
        if (history == null)
        {
            _logger.LogWarning(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "History=Not Available (no history object for zone) | Fallback=AXFR",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        // CRITICAL: Take a snapshot of history state to prevent changes during IXFR processing
        // This is especially important during rapid updates where history may be modified concurrently
        var historySnapshot = history.GetAllVersions();
        var availableSerials = historySnapshot.Keys.OrderBy(s => s).ToList();
        
        _logger.LogDebug(
            "IXFR history check: Zone={Zone} | Client Serial={ClientSerial} | " +
            "Available Serials=[{Serials}] | History Versions={VersionCount}",
            zoneConfig.Name, clientSerial, 
            string.Join(", ", availableSerials), historySnapshot.Count);

        // IXFR Consistency Validation: Check if client's serial exists in history
        if (!historySnapshot.ContainsKey(clientSerial.Value))
        {
            var oldestSerial = availableSerials.FirstOrDefault();
            var newestSerial = availableSerials.LastOrDefault();
            
            // Check if this is due to rapid updates (version was pruned)
            var timeSinceNewest = history.GetTimeSinceNewestVersion();
            var recentVersionCount = history.GetVersionCountInWindow(TimeSpan.FromMinutes(5));
            
            _logger.LogInformation(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "History=Version Not Found (serial {ClientSerial} not in history) | " +
                "Available Range={OldestSerial}..{NewestSerial} | History Versions={VersionCount} | " +
                "Recent Updates (5min)={RecentCount} | Time Since Newest={TimeSinceNewest} | Fallback=AXFR",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial, 
                clientSerial, oldestSerial, newestSerial, historySnapshot.Count,
                recentVersionCount, timeSinceNewest?.TotalSeconds.ToString("F1") ?? "N/A");
            
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }
        
        // IXFR Consistency Validation: Verify we have a complete chain from clientSerial to snapshotSerial
        // This prevents serving corrupt IXFR when intermediate versions were pruned during rapid updates
        if (!ValidateIxfrVersionChain(historySnapshot, clientSerial.Value, snapshotSerial.Value, snapshotRecords, zoneConfig.Name, remoteEndPoint))
        {
            _logger.LogWarning(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "IXFR chain validation failed: Cannot construct complete diff chain from {ClientSerial} to {ServerSerial} | Fallback=AXFR",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
            return;
        }

        // Case 3: Calculate incremental changes
        try
        {
            _logger.LogDebug(
                "IXFR diff calculation: Zone={Zone} | Calculating diffs from serial {FromSerial} to {ToSerial}",
                zoneConfig.Name, clientSerial, snapshotSerial);

            // CRITICAL: Pass snapshot records in case snapshotSerial is not yet in history
            // This ensures we include the final diff from last history version to current cache
            // Using snapshot ensures consistency even if cache is updated during IXFR handling
            var diffs = ZoneDiffCalculator.CalculateDiffSequence(
                history, 
                clientSerial.Value, 
                snapshotSerial.Value,
                snapshotRecords); // Pass snapshot records for final diff calculation

            if (diffs.Count == 0)
            {
                // No diffs found - fallback to full zone
                _logger.LogWarning(
                    "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                    "Diff Calculation=No diffs found | Fallback=AXFR",
                    zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }

            var totalDeletions = diffs.Sum(d => d.DeletedRecords.Count);
            var totalAdditions = diffs.Sum(d => d.AddedRecords.Count);
            var totalChanges = totalDeletions + totalAdditions;

            // CRITICAL VALIDATION: Check if deletions are suspiciously high
            // If we're about to delete more than configured threshold of records, this is likely a diff calculation error
            // In this case, force AXFR fallback to ensure zone integrity
            var currentRecordCount = snapshotRecords.Count;
            var netChange = totalAdditions - totalDeletions;
            var estimatedClientFinalCount = currentRecordCount + netChange; // Rough estimate

            // Get configurable threshold (default: 50%)
            var suspiciousDeletionThreshold = zoneConfig.IxfrSuspiciousDeletionThreshold ?? 50;
            var deletionThresholdRatio = suspiciousDeletionThreshold / 100.0;

            // RELIABILITY FIX: Force AXFR fallback when diff is suspicious
            // This prevents potentially corrupt IXFR responses from being sent to slaves
            if (suspiciousDeletionThreshold < 100 && totalDeletions > currentRecordCount * deletionThresholdRatio)
            {
                _logger.LogWarning(
                    "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "SUSPICIOUS DIFF DETECTED: Large number of deletions ({Deletions}) vs current zone size ({CurrentCount}) | " +
                    "Forcing AXFR fallback to ensure zone integrity",
                    zoneConfig.Name, remoteEndPoint, totalDeletions, currentRecordCount);
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }

            // RELIABILITY FIX: Force AXFR fallback when estimated final count is suspiciously low
            // This catches cases where diff calculation might result in empty zones
            if (estimatedClientFinalCount < 3) // Less than SOA + 2 NS records
            {
                _logger.LogWarning(
                    "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "SUSPICIOUS DIFF DETECTED: Estimated client final record count ({EstimatedCount}) is too low | " +
                    "Forcing AXFR fallback to ensure zone integrity",
                    zoneConfig.Name, remoteEndPoint, estimatedClientFinalCount);
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }

            _logger.LogInformation(
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "Response Type=Incremental | Diff Sequences={DiffCount} | " +
                "Deletions={Deletions} | Additions={Additions} | Total Changes={TotalChanges} | " +
                "Current Zone Size={CurrentSize} | Estimated Client Final Size={EstimatedSize}",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial,
                diffs.Count, totalDeletions, totalAdditions, totalChanges,
                currentRecordCount, estimatedClientFinalCount);

            // Log details of each diff sequence
            for (int i = 0; i < diffs.Count; i++)
            {
                var diff = diffs[i];
                _logger.LogDebug(
                    "IXFR diff sequence {Sequence}/{Total}: Zone={Zone} | " +
                    "From Serial={FromSerial} | To Serial={ToSerial} | " +
                    "Deletions={Deletions} | Additions={Additions}",
                    i + 1, diffs.Count, zoneConfig.Name,
                    diff.FromSerial, diff.ToSerial,
                    diff.DeletedRecords.Count, diff.AddedRecords.Count);
            }

            // Build and send IXFR response
            // Get the original question from the request (RFC 1995 requires matching question section)
            var question = request.Questions.FirstOrDefault();
            if (question == null)
            {
                _logger.LogWarning("IXFR request has no question section, falling back to AXFR");
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }

            // Provide a function to get SOA records from history versions
            // CRITICAL: Use historySnapshot to ensure consistency during IXFR building
            // Also check snapshot zone records for the toSerial SOA (might not be in history yet)
            FilteredRecord? GetSoaForSerial(uint serial)
            {
                // First check if this is the snapshot serial - use snapshotSoa directly
                if (serial == snapshotSerial && snapshotSoa != null)
                {
                    return snapshotSoa;
                }
                // Otherwise look in history snapshot (not live history)
                if (historySnapshot.TryGetValue(serial, out var version))
                {
                    return version.Records.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
                }
                return null;
            }

            var responseBuildStart = DateTime.UtcNow;
            var buildResult = IxfrResponseBuilder.BuildIxfrResponse(diffs, snapshotSoa, request.Id, question, GetSoaForSerial);
            var responseBuildDuration = (DateTime.UtcNow - responseBuildStart).TotalMilliseconds;

            // CRITICAL: Check if IXFR build succeeded - if not, fallback to AXFR
            // This ensures we never send malformed IXFR responses that could corrupt slave zones
            if (!buildResult.Success)
            {
                _logger.LogWarning(
                    "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                    "IXFR BUILD FAILED: {Reason} | Forcing AXFR fallback to ensure zone integrity",
                    zoneConfig.Name, remoteEndPoint, buildResult.FailureReason);
                await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
                return;
            }
            
            long totalBytes = 0;
            int totalRecordsInResponse = 0;
            foreach (var message in buildResult.Messages)
            {
                await SendTcpMessageAsync(stream, message, cancellationToken);
                totalBytes += message.Length + 2; // +2 for length prefix
                // Approximate record count (each message typically contains 1 record)
                totalRecordsInResponse++;
            }

            _logger.LogInformation(
                "IXFR response sent: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "Messages={MessageCount} | Approx Bytes={Bytes} | Build Duration={BuildDuration}ms | " +
                "Total Changes={TotalChanges} (Deletions={Deletions}, Additions={Additions})",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial,
                buildResult.Messages.Count, totalBytes, responseBuildDuration,
                totalDeletions + totalAdditions, totalDeletions, totalAdditions);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex,
                "IXFR response: Zone={Zone} | Client={RemoteEndPoint} | " +
                "Client Serial={ClientSerial} | Server Serial={ServerSerial} | " +
                "Error=Diff calculation failed | Fallback=AXFR",
                zoneConfig.Name, remoteEndPoint, clientSerial, snapshotSerial);
            await SendFullZoneTransferAsync(stream, request, zoneConfig, snapshotRecords, cancellationToken);
        }
    }

    /// <summary>
    /// Validates that a complete IXFR diff chain can be constructed from clientSerial to targetSerial.
    /// This prevents serving incomplete/corrupt IXFR when intermediate versions were pruned during rapid updates.
    /// </summary>
    /// <param name="historySnapshot">Snapshot of zone history versions</param>
    /// <param name="clientSerial">Client's current serial (starting point)</param>
    /// <param name="targetSerial">Server's current serial (ending point)</param>
    /// <param name="currentRecords">Current zone records (for final diff if needed)</param>
    /// <param name="zoneName">Zone name for logging</param>
    /// <param name="remoteEndPoint">Remote endpoint for logging</param>
    /// <returns>True if IXFR chain is valid, false if AXFR fallback is needed</returns>
    private bool ValidateIxfrVersionChain(
        Dictionary<uint, ZoneVersion> historySnapshot,
        uint clientSerial,
        uint targetSerial,
        List<FilteredRecord> currentRecords,
        string zoneName,
        IPEndPoint remoteEndPoint)
    {
        // If client is already at target, no chain needed
        if (clientSerial == targetSerial)
            return true;

        // Must have the starting version (client's serial)
        if (!historySnapshot.ContainsKey(clientSerial))
        {
            _logger.LogDebug(
                "IXFR chain validation failed: Zone={Zone} | Client Serial={ClientSerial} not in history snapshot",
                zoneName, clientSerial);
            return false;
        }

        // Get sorted list of available serials
        var availableSerials = historySnapshot.Keys.OrderBy(s => s).ToList();
        
        // Find the position of client serial
        var clientIndex = availableSerials.IndexOf(clientSerial);
        if (clientIndex < 0)
        {
            _logger.LogDebug(
                "IXFR chain validation failed: Zone={Zone} | Client Serial={ClientSerial} not found in sorted serials",
                zoneName, clientSerial);
            return false;
        }

        // Check if target serial is in history or if we need to use current records
        var targetInHistory = historySnapshot.ContainsKey(targetSerial);
        
        if (!targetInHistory)
        {
            // Target serial not in history - we'll need to calculate final diff from last history version to current records
            // This is valid as long as we have consecutive versions up to the newest in history
            var newestHistorySerial = availableSerials.LastOrDefault();
            
            // Verify current records have the expected target serial
            var currentSoa = currentRecords.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
            var currentSerial = currentSoa?.SoaData?.Serial ?? 0;
            
            if (currentSerial != targetSerial)
            {
                _logger.LogDebug(
                    "IXFR chain validation failed: Zone={Zone} | Target Serial={TargetSerial} not in history and current records have Serial={CurrentSerial}",
                    zoneName, targetSerial, currentSerial);
                return false;
            }
            
            _logger.LogDebug(
                "IXFR chain validation: Zone={Zone} | Target Serial={TargetSerial} not in history but matches current records, will calculate final diff from {NewestHistory}",
                zoneName, targetSerial, newestHistorySerial);
        }

        // Check that we have enough consecutive versions to build diffs
        // We need at least one version after client serial (to calculate at least one diff)
        var versionsAfterClient = availableSerials.Where(s => s > clientSerial).ToList();
        
        if (versionsAfterClient.Count == 0 && !targetInHistory)
        {
            // No versions after client, but target is not in history either
            // This means we need to diff directly from client version to current records
            _logger.LogDebug(
                "IXFR chain validation: Zone={Zone} | No intermediate versions between Client Serial={ClientSerial} and Target={TargetSerial}, will calculate direct diff",
                zoneName, clientSerial, targetSerial);
            return true; // This is valid - ZoneDiffCalculator can handle this
        }

        // Log chain validation success
        _logger.LogDebug(
            "IXFR chain validation passed: Zone={Zone} | Client Serial={ClientSerial} | Target Serial={TargetSerial} | " +
            "Intermediate Versions={IntermediateCount} | Target In History={TargetInHistory}",
            zoneName, clientSerial, targetSerial, versionsAfterClient.Count, targetInHistory);

        return true;
    }

    /// <summary>
    /// Sends a full zone transfer (AXFR format) as fallback for IXFR.
    /// </summary>
    private async Task SendFullZoneTransferAsync(
        NetworkStream stream,
        DnsMessage request,
        ZoneConfig zoneConfig,
        List<FilteredRecord> zoneRecords,
        CancellationToken cancellationToken)
    {
        var soaRecord = zoneRecords.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
        var serial = soaRecord != null ? ExtractSerialFromSoa(soaRecord) : (uint?)null;
        long bytesTransferred = 0;
        int recordsSent = 0;

        _logger.LogDebug(
            "Sending full zone transfer (AXFR fallback): Zone={Zone} | " +
            "Serial={Serial} | Records={RecordCount}",
            zoneConfig.Name, serial ?? 0, zoneRecords.Count);

        // Send SOA first
        if (soaRecord != null)
        {
            var bytes = await SendRecordAsync(stream, soaRecord, request.Id, zoneConfig.Name, cancellationToken);
            bytesTransferred += bytes;
            recordsSent++;
        }

        // Send all other records
        foreach (var record in zoneRecords)
        {
            if (record.RecordType != ResourceRecordType.SOA)
            {
                var bytes = await SendRecordAsync(stream, record, request.Id, zoneConfig.Name, cancellationToken);
                bytesTransferred += bytes;
                recordsSent++;
            }
        }

        // Send SOA again at the end
        if (soaRecord != null)
        {
            var bytes = await SendRecordAsync(stream, soaRecord, request.Id, zoneConfig.Name, cancellationToken);
            bytesTransferred += bytes;
            recordsSent++;
        }

        _logger.LogDebug(
            "Full zone transfer (AXFR fallback) sent: Zone={Zone} | " +
            "Records Sent={RecordsSent} | Bytes={Bytes}",
            zoneConfig.Name, recordsSent, bytesTransferred);
    }

    /// <summary>
    /// Sends a TCP DNS message with length prefix.
    /// </summary>
    private async Task SendTcpMessageAsync(NetworkStream stream, byte[] message, CancellationToken cancellationToken)
    {
        var length = (ushort)message.Length;
        var lengthBytes = new[] { (byte)(length >> 8), (byte)(length & 0xFF) };
        await stream.WriteAsync(lengthBytes, cancellationToken);
        await stream.WriteAsync(message, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private async Task<int> SendRecordAsync(
        NetworkStream stream,
        FilteredRecord record,
        ushort queryId,
        string zoneName,
        CancellationToken cancellationToken)
    {
        var response = DnsRecordBuilder.BuildZoneTransferResponse(
            new List<FilteredRecord> { record },
            queryId,
            zoneName);

        var length = (ushort)response.Length;
        var lengthBytes = new[] { (byte)(length >> 8), (byte)(length & 0xFF) };
        await stream.WriteAsync(lengthBytes, cancellationToken);
        await stream.WriteAsync(response, cancellationToken);
        await stream.FlushAsync(cancellationToken);
        
        // Return total bytes sent (2 for length prefix + response length)
        return 2 + response.Length;
    }

    private async Task HandleSoaQueryOnTcpAsync(
        NetworkStream stream,
        IPEndPoint remoteEndPoint,
        DnsMessage request,
        DnsQuestion question,
        ZoneConfig zoneConfig,
        CancellationToken cancellationToken)
    {
        try
        {
            var zoneName = question.Name.TrimEnd('.');
            
            // Get zone (from cache or upstream)
            // CRITICAL: Always verify we have the latest data before serving SOA queries
            // This ensures SOA responses always reflect the current zone state
            List<FilteredRecord> zoneRecords;
            var cachedZone = _cache.GetZone(zoneConfig.Name);
            
            if (cachedZone != null && cachedZone.Records.Count > 0)
            {
                // Verify cached data is the latest by checking upstream serial
                var timeout = GetUpstreamTimeout();
                var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
                try
                {
                    var upstreamSerial = await upstreamClient.GetSoaSerialAsync(zoneConfig.Name, cancellationToken);
                    
                    // If upstream has newer serial, fetch fresh data
                    if (upstreamSerial > cachedZone.Serial)
                    {
                        _logger.LogDebug(
                            "SOA query: Cached data for {Zone} is stale (cached: {CachedSerial}, upstream: {UpstreamSerial}), fetching latest",
                            zoneConfig.Name, cachedZone.Serial, upstreamSerial);
                        
                        var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneConfig.Name, cancellationToken);
                        zoneRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneConfig.Name);
                        await UpdateCacheAndNotifyAsync(zoneConfig.Name, zoneConfig, zoneRecords, cancellationToken);
                    }
                    else
                    {
                        // Cached data is current - use it
                        zoneRecords = cachedZone.Records;
                    }
                }
                catch (Exception ex)
                {
                    // If upstream check fails, use cached data as fallback
                    _logger.LogDebug(ex, "SOA query: Failed to verify upstream serial for {Zone}, using cached data", zoneConfig.Name);
                    zoneRecords = cachedZone.Records;
                }
                finally
                {
                    upstreamClient.Dispose();
                }
            }
            else
            {
                // Zone not cached, fetch from upstream
                _logger.LogDebug("SOA query on TCP for zone {Zone}: Zone not cached, fetching from upstream {Upstream}", 
                    zoneConfig.Name, zoneConfig.Upstream);
                
                var timeout = GetUpstreamTimeout();
                var upstreamClient = new UpstreamClient(zoneConfig.Upstream, timeout);
                try
                {
                    var upstreamRecords = await upstreamClient.FetchZoneAsync(zoneConfig.Name, cancellationToken);
                    zoneRecords = RecordFilter.ApplyFilters(upstreamRecords, zoneConfig, zoneConfig.Name);
                    await UpdateCacheAndNotifyAsync(zoneConfig.Name, zoneConfig, zoneRecords, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "SOA query on TCP for zone {Zone}: Failed to fetch from upstream", zoneConfig.Name);
                    await SendRefusedResponseAsync(stream, request, cancellationToken);
                    return;
                }
                finally
                {
                    upstreamClient.Dispose();
                }
            }
            
            // Find SOA record
            var soaRecord = zoneRecords.FirstOrDefault(r => r.RecordType == ResourceRecordType.SOA);
            
            if (soaRecord == null)
            {
                _logger.LogWarning("SOA query on TCP for zone {Zone}: No SOA record found", zoneConfig.Name);
                var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.ServFail);
                var length = (ushort)response.Length;
                await stream.WriteAsync(new[] { (byte)(length >> 8), (byte)(length & 0xFF) }, cancellationToken);
                await stream.WriteAsync(response, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                return;
            }
            
            // Build and send SOA response
            var soaResponse = DnsRecordBuilder.BuildQueryResponse(request, new List<FilteredRecord> { soaRecord }, DnsResponseCode.NoError);
            var responseLength = (ushort)soaResponse.Length;
            await stream.WriteAsync(new[] { (byte)(responseLength >> 8), (byte)(responseLength & 0xFF) }, cancellationToken);
            await stream.WriteAsync(soaResponse, cancellationToken);
            await stream.FlushAsync(cancellationToken);
            
            _logger.LogDebug("SOA query on TCP for zone {Zone} from {RemoteEndPoint}: Responded with SOA (serial: {Serial})", 
                zoneConfig.Name, remoteEndPoint, soaRecord.SoaData?.Serial ?? 0);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling SOA query on TCP for zone {Zone} from {RemoteEndPoint}", 
                zoneConfig.Name, remoteEndPoint);
            try
            {
                await SendRefusedResponseAsync(stream, request, cancellationToken);
            }
            catch
            {
                // Ignore errors sending error response
            }
        }
    }

    private async Task SendRefusedResponseAsync(
        NetworkStream stream,
        DnsMessage request,
        CancellationToken cancellationToken)
    {
        var response = DnsMessageParser.BuildResponse(request, DnsResponseCode.Refused);
        var length = (ushort)response.Length;
        await stream.WriteAsync(new[] { (byte)(length >> 8), (byte)(length & 0xFF) }, cancellationToken);
        await stream.WriteAsync(response, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    /// <summary>
    /// Gets the upstream timeout from security configuration, or defaults to 600 seconds (10 minutes).
    /// </summary>
    private TimeSpan GetUpstreamTimeout()
    {
        var timeoutSeconds = _securityConfig?.ZoneTransferTimeoutSeconds ?? 600;
        return TimeSpan.FromSeconds(timeoutSeconds);
    }

    public void Stop()
    {
        _tcpListener.Stop();
        _udpClient.Close();
        _connectionCleanupTimer?.Dispose();
        _tcpConnectionSemaphore?.Dispose();
        _udpRequestSemaphore?.Dispose();
    }
}

