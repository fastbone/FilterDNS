using System.Collections.Concurrent;
using System.Net;
using DnsClient.Protocol;
using FilterDns.Alert;
using FilterDns.Config;
using FilterDns.Notify;
using FilterDns.Recovery;
using FilterDns.Slave;
using Microsoft.Extensions.Logging;

namespace FilterDns.Verify;

public class SlaveVerificationService
{
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _pendingVerifications = new();
    private readonly ConcurrentDictionary<string, int> _verificationRetryCount = new();
    private readonly ILogger<SlaveVerificationService> _logger;
    private readonly EmailAlertService? _emailAlertService;
    private readonly SelfRestartService? _selfRestartService;

    public SlaveVerificationService(
        ILogger<SlaveVerificationService> logger,
        EmailAlertService? emailAlertService = null,
        SelfRestartService? selfRestartService = null)
    {
        _logger = logger;
        _emailAlertService = emailAlertService;
        _selfRestartService = selfRestartService;
    }

    /// <summary>
    /// Schedules a delayed verification task for a zone after NOTIFY has been sent.
    /// </summary>
    /// <param name="zoneName">The zone name that was notified</param>
    /// <param name="sentSerial">The SOA serial number that was sent to slaves</param>
    /// <param name="sentRecordCount">The number of records that were sent to slaves</param>
    /// <param name="slaves">List of slave servers to verify</param>
    /// <param name="delaySeconds">Delay in seconds before starting verification</param>
    /// <param name="recordCountTolerance">Acceptable difference in record count (default: 0)</param>
    /// <param name="notifySender">Optional notify sender to re-trigger NOTIFY on mismatch</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <param name="clearHistoryCallback">Callback to clear zone history (forces AXFR on next request)</param>
    /// <param name="clearHistoryOnMismatch">Whether to clear history when mismatch is detected</param>
    /// <param name="maxRetries">Maximum number of verification retries before giving up</param>
    public void ScheduleVerification(
        string zoneName,
        uint sentSerial,
        int sentRecordCount,
        List<SlaveConfig> slaves,
        int delaySeconds,
        int recordCountTolerance = 0,
        NotifySender? notifySender = null,
        CancellationToken cancellationToken = default,
        Action<string>? clearHistoryCallback = null,
        bool clearHistoryOnMismatch = true,
        int maxRetries = 3)
    {
        if (slaves == null || slaves.Count == 0)
        {
            _logger.LogDebug("No slaves configured for zone {Zone}, skipping verification", zoneName);
            return;
        }

        // Cancel any existing verification for this zone
        if (_pendingVerifications.TryRemove(zoneName, out var existingCts))
        {
            existingCts.Cancel();
            existingCts.Dispose();
        }

        // Create cancellation token source for this verification
        var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _pendingVerifications[zoneName] = cts;

        // Capture the token before scheduling the task to avoid disposal issues
        var verificationToken = cts.Token;

        // Schedule verification task
        _ = Task.Run(async () =>
        {
            try
            {
                // Wait for the configured delay
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), verificationToken);
                
                _logger.LogInformation(
                    "Starting slave verification for zone {Zone} (expected serial: {Serial}, expected records: {RecordCount})",
                    zoneName, sentSerial, sentRecordCount);

                // Verify each slave - use captured token instead of accessing cts.Token
                // Collect results to determine if we need to force AXFR
                var results = new ConcurrentBag<(SlaveConfig Slave, bool Success, bool Mismatch)>();
                
                var verificationTasks = slaves
                    .Where(s => s.IsValid())
                    .Select(async slave => 
                    {
                        var result = await VerifySlaveWithResultAsync(
                            zoneName, slave, sentSerial, sentRecordCount, 
                            recordCountTolerance, verificationToken);
                        results.Add((slave, result.Success, result.Mismatch));
                        return result;
                    });

                await Task.WhenAll(verificationTasks);

                // Check if any slave has a mismatch
                var mismatchedSlaves = results.Where(r => r.Mismatch).ToList();
                
                if (mismatchedSlaves.Count > 0)
                {
                    // Get current retry count
                    var currentRetry = _verificationRetryCount.AddOrUpdate(zoneName, 1, (_, count) => count + 1);
                    
                    _logger.LogWarning(
                        "Slave verification mismatch for zone {Zone}: {MismatchCount}/{TotalCount} slaves have incorrect data | " +
                        "Retry attempt: {RetryAttempt}/{MaxRetries}",
                        zoneName, mismatchedSlaves.Count, results.Count, currentRetry, maxRetries);

                    if (currentRetry <= maxRetries)
                    {
                        // RELIABILITY FIX: Clear history to force AXFR on next transfer
                        if (clearHistoryOnMismatch && clearHistoryCallback != null)
                        {
                            _logger.LogWarning(
                                "Clearing zone history for {Zone} to force AXFR on next transfer request",
                                zoneName);
                            clearHistoryCallback(zoneName);
                        }

                        // Re-trigger NOTIFY to force slaves to re-transfer
                        if (notifySender != null)
                        {
                            _logger.LogInformation(
                                "Re-triggering NOTIFY for zone {Zone} due to verification mismatch (history cleared, AXFR will be used)",
                                zoneName);
                            try
                            {
                                await notifySender.NotifyAllAsync(zoneName, verificationToken);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Failed to re-trigger NOTIFY for zone {Zone} after mismatch", zoneName);
                            }
                        }

                        _ = Task.Run(async () =>
                        {
                            try
                            {
                                while (_pendingVerifications.TryGetValue(zoneName, out var pendingCts) && ReferenceEquals(pendingCts, cts))
                                {
                                    await Task.Delay(10, cancellationToken);
                                }

                                if (_pendingVerifications.ContainsKey(zoneName))
                                {
                                    _logger.LogDebug(
                                        "Skipping retry verification for zone {Zone} because a newer verification is already pending",
                                        zoneName);
                                    return;
                                }

                                ScheduleVerification(
                                    zoneName,
                                    sentSerial,
                                    sentRecordCount,
                                    slaves,
                                    delaySeconds,
                                    recordCountTolerance,
                                    notifySender,
                                    cancellationToken,
                                    clearHistoryCallback,
                                    clearHistoryOnMismatch,
                                    maxRetries);
                            }
                            catch (OperationCanceledException)
                            {
                                _logger.LogDebug("Retry verification scheduling cancelled for zone {Zone}", zoneName);
                            }
                        }, CancellationToken.None);
                    }
                    else
                    {
                        _logger.LogError(
                            "CRITICAL: Slave verification for zone {Zone} failed after {MaxRetries} retries | " +
                            "Zone may be unhealthy - considering self-restart",
                            zoneName, maxRetries);
                        
                        // Report to self-restart service for potential recovery
                        if (_selfRestartService != null)
                        {
                            _selfRestartService.ReportCriticalError(
                                "SlaveVerificationService",
                                $"Zone {zoneName} verification failed after {maxRetries} retries with {mismatchedSlaves.Count} mismatched slaves");
                        }
                        
                        // Send email alert for critical failure
                        if (_emailAlertService != null)
                        {
                            try
                            {
                                await _emailAlertService.SendCriticalAlertAsync(
                                    $"Zone {zoneName} verification failed",
                                    $"Slave verification for zone {zoneName} failed after {maxRetries} retries. " +
                                    $"{mismatchedSlaves.Count} slaves have incorrect data. " +
                                    $"Self-restart may be triggered if configured.",
                                    verificationToken);
                            }
                            catch (Exception ex)
                            {
                                _logger.LogWarning(ex, "Failed to send critical alert email for zone {Zone}", zoneName);
                            }
                        }
                    }
                }
                else
                {
                    // All slaves verified successfully - reset retry counter and report success
                    _verificationRetryCount.TryRemove(zoneName, out _);
                    _selfRestartService?.ReportZoneSuccess(zoneName);
                    _logger.LogInformation("Slave verification completed successfully for zone {Zone}", zoneName);
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogDebug("Slave verification cancelled for zone {Zone}", zoneName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during slave verification for zone {Zone}", zoneName);
            }
            finally
            {
                // Clean up - only dispose after all tasks complete
                if (_pendingVerifications.TryRemove(new KeyValuePair<string, CancellationTokenSource>(zoneName, cts)))
                {
                    try
                    {
                        cts.Dispose();
                    }
                    catch (ObjectDisposedException)
                    {
                        // Already disposed, ignore
                    }
                }
            }
        }, verificationToken);
    }

    /// <summary>
    /// Result of verifying a single slave.
    /// </summary>
    private class VerificationResult
    {
        public bool Success { get; set; }
        public bool Mismatch { get; set; }
    }

    /// <summary>
    /// Verifies a single slave server and returns the result.
    /// </summary>
    private async Task<VerificationResult> VerifySlaveWithResultAsync(
        string zoneName,
        SlaveConfig slave,
        uint expectedSerial,
        int expectedRecordCount,
        int recordCountTolerance,
        CancellationToken cancellationToken)
    {
        var result = new VerificationResult { Success = false, Mismatch = false };
        
        var slaveIp = slave.GetIpAddress();
        if (slaveIp == null)
        {
            _logger.LogWarning("Skipping verification for invalid slave IP {Ip} for zone {Zone}", slave.Ip, zoneName);
            return result;
        }

        var slaveEndpoint = new IPEndPoint(slaveIp, slave.Port);

        try
        {
            // Step 1: Query SOA record from slave
            _logger.LogDebug("Querying SOA from slave {SlaveIp}:{Port} for zone {Zone}", slaveIp, slave.Port, zoneName);
            
            uint receivedSerial;
            try
            {
                receivedSerial = await SlaveClient.QuerySoaAsync(zoneName, slaveEndpoint, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to query SOA from slave {SlaveIp}:{Port} for zone {Zone}", 
                    slaveIp, slave.Port, zoneName);
                return result; // Don't trigger alarm on network/query failures
            }

            _logger.LogDebug("Received SOA serial {Serial} from slave {SlaveIp}:{Port} for zone {Zone} (expected: {ExpectedSerial})",
                receivedSerial, slaveIp, slave.Port, zoneName, expectedSerial);

            // Step 2: Compare serial numbers
            bool serialMismatch = receivedSerial != expectedSerial;
            
            // Step 3: Fetch zone from slave via AXFR to compare record count
            int receivedRecordCount = 0;
            bool recordCountMismatch = false;
            bool isEmptyZone = false;
            
            try
            {
                _logger.LogDebug("Initiating AXFR from slave {SlaveIp}:{Port} for zone {Zone} to compare records",
                    slaveIp, slave.Port, zoneName);
                
                var slaveRecords = await SlaveClient.FetchZoneFromSlaveAsync(zoneName, slaveEndpoint, cancellationToken);
                receivedRecordCount = slaveRecords.Count;
                
                // Check if record count difference is within tolerance
                var recordCountDifference = Math.Abs(receivedRecordCount - expectedRecordCount);
                recordCountMismatch = recordCountDifference > recordCountTolerance;
                
                // CRITICAL: Check for empty zone (only SOA/NS records or very few records)
                isEmptyZone = receivedRecordCount <= 3;

                _logger.LogDebug("Received {RecordCount} records from slave {SlaveIp}:{Port} for zone {Zone} (expected: {ExpectedCount}, tolerance: {Tolerance}, difference: {Difference}, isEmpty: {IsEmpty})",
                    receivedRecordCount, slaveIp, slave.Port, zoneName, expectedRecordCount, recordCountTolerance, recordCountDifference, isEmptyZone);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to fetch zone from slave {SlaveIp}:{Port} for zone {Zone}",
                    slaveIp, slave.Port, zoneName);
                // Continue with serial comparison only
            }

            // Step 4: Check for mismatches
            if (serialMismatch || recordCountMismatch || isEmptyZone)
            {
                result.Mismatch = true;
                
                var mismatchTypes = new List<string>();
                if (serialMismatch) mismatchTypes.Add("Serial");
                if (recordCountMismatch) mismatchTypes.Add("RecordCount");
                if (isEmptyZone) mismatchTypes.Add("EmptyZone");

                var recordCountDifference = Math.Abs(receivedRecordCount - expectedRecordCount);
                
                // CRITICAL: Log empty zones as errors (these are the most serious)
                if (isEmptyZone)
                {
                    _logger.LogError(
                        "CRITICAL: Empty zone detected on slave {SlaveIp}:{Port} for zone {Zone} | " +
                        "Slave has only {ReceivedRecordCount} records (expected: {ExpectedRecordCount}) | " +
                        "This indicates a failed zone transfer - forcing full retransfer",
                        slaveIp, slave.Port, zoneName, receivedRecordCount, expectedRecordCount);
                }
                else
                {
                    _logger.LogError(
                        "Slave verification mismatch detected for zone {Zone} on slave {SlaveIp}:{Port} | " +
                        "Expected Serial: {ExpectedSerial}, Received Serial: {ReceivedSerial} | " +
                        "Expected Record Count: {ExpectedRecordCount}, Received Record Count: {ReceivedRecordCount} | " +
                        "Record Count Difference: {RecordCountDifference}, Tolerance: {Tolerance} | " +
                        "Mismatch Types: {MismatchTypes}",
                        zoneName, slaveIp, slave.Port,
                        expectedSerial, receivedSerial,
                        expectedRecordCount, receivedRecordCount,
                        recordCountDifference, recordCountTolerance,
                        string.Join(", ", mismatchTypes));
                }

                _selfRestartService?.ReportVerificationFailure(
                    zoneName,
                    $"{slaveIp}:{slave.Port}",
                    string.Join(",", mismatchTypes));

                // Send email alert for verification issue
                if (_emailAlertService != null)
                {
                    try
                    {
                        await _emailAlertService.SendVerificationAlertAsync(
                            zoneName,
                            slaveIp.ToString(),
                            slave.Port,
                            expectedSerial,
                            receivedSerial,
                            expectedRecordCount,
                            receivedRecordCount,
                            recordCountDifference,
                            recordCountTolerance,
                            mismatchTypes,
                            cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to send email alert for verification mismatch");
                    }
                }
            }
            else
            {
                result.Success = true;
                _logger.LogInformation(
                    "Slave verification passed for zone {Zone} on slave {SlaveIp}:{Port} | " +
                    "Serial: {Serial}, Record Count: {RecordCount}",
                    zoneName, slaveIp, slave.Port, receivedSerial, receivedRecordCount);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Verification cancelled for slave {SlaveIp}:{Port} for zone {Zone}", slaveIp, slave.Port, zoneName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error verifying slave {SlaveIp}:{Port} for zone {Zone}", 
                slaveIp, slave.Port, zoneName);
        }
        
        return result;
    }

    /// <summary>
    /// Cancels any pending verification for the specified zone.
    /// </summary>
    public void CancelVerification(string zoneName)
    {
        if (_pendingVerifications.TryRemove(zoneName, out var cts))
        {
            cts.Cancel();
            cts.Dispose();
        }
    }

    /// <summary>
    /// Cancels all pending verifications.
    /// </summary>
    public void CancelAllVerifications()
    {
        foreach (var kvp in _pendingVerifications)
        {
            kvp.Value.Cancel();
            kvp.Value.Dispose();
        }
        _pendingVerifications.Clear();
    }
}
