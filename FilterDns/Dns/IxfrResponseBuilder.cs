using System.Net;
using FilterDns.Filter;
using FilterDns.Xfer;

namespace FilterDns.Dns;

/// <summary>
/// Result of IXFR response building - indicates success or failure reason.
/// </summary>
public class IxfrBuildResult
{
    public bool Success { get; set; }
    public List<byte[]> Messages { get; set; } = new();
    public string? FailureReason { get; set; }
    
    public static IxfrBuildResult Succeeded(List<byte[]> messages) => new() { Success = true, Messages = messages };
    public static IxfrBuildResult Failed(string reason) => new() { Success = false, FailureReason = reason };
}

/// <summary>
/// Builds RFC 1995-compliant IXFR (Incremental Zone Transfer) responses.
/// </summary>
public static class IxfrResponseBuilder
{
    /// <summary>
    /// Builds an IXFR response with incremental changes.
    /// Format per RFC 1995:
    /// - Current SOA
    /// - For each diff sequence:
    ///   - Old SOA (preceding deletions) - MUST be from FromSerial version
    ///   - Deleted records
    ///   - New SOA (preceding additions) - MUST be from ToSerial version
    ///   - Added records
    /// - Final current SOA
    /// 
    /// CRITICAL: Returns failure if SOA records are missing - caller MUST fallback to AXFR.
    /// Per RFC 1995, IXFR responses without proper SOA boundaries are malformed and can
    /// cause slave servers to end up with empty or corrupt zones.
    /// </summary>
    public static IxfrBuildResult BuildIxfrResponse(
        List<ZoneDiff> diffs,
        FilteredRecord currentSoa,
        ushort queryId,
        DnsQuestion originalQuestion,
        Func<uint, FilteredRecord?>? getSoaForSerial = null)
    {
        if (diffs == null)
            throw new ArgumentNullException(nameof(diffs));
        if (currentSoa == null)
            throw new ArgumentNullException(nameof(currentSoa));
        if (originalQuestion == null)
            throw new ArgumentNullException(nameof(originalQuestion));

        var messages = new List<byte[]>();
        
        // Use the exact question from the request (RFC 1995 requires matching question section)
        var questionName = originalQuestion.Name;
        var normalizedZoneName = questionName.EndsWith('.') ? questionName : $"{questionName}.";

        // Send current SOA first (must include question section matching request)
        // Each message gets its own compression dictionary (compression is per-message, not across messages)
        var firstMessageCompression = new Dictionary<string, int>();
        var currentSoaMessage = BuildSoaMessage(currentSoa, queryId, originalQuestion, firstMessageCompression, isFirst: true);
        messages.Add(currentSoaMessage);

        // Process each diff sequence
        foreach (var diff in diffs)
        {
            // Get SOA records for old and new versions
            // RFC 1995 requires SOA records from the actual versions, not from diff
            FilteredRecord? oldSoa = null;
            FilteredRecord? newSoa = null;

            // Try to get SOA from the version lookup function first (most reliable)
            if (getSoaForSerial != null)
            {
                oldSoa = getSoaForSerial(diff.FromSerial);
                newSoa = getSoaForSerial(diff.ToSerial);
            }

            // Fallback: try to find SOA in diff records if lookup function not available
            if (oldSoa == null)
            {
                oldSoa = diff.DeletedRecords.FirstOrDefault(r => r.RecordType == DnsClient.Protocol.ResourceRecordType.SOA);
            }
            if (newSoa == null)
            {
                newSoa = diff.AddedRecords.FirstOrDefault(r => r.RecordType == DnsClient.Protocol.ResourceRecordType.SOA);
            }

            // CRITICAL: RFC 1995 requires SOA records to delimit deletions and additions.
            // If we don't have SOA records, the IXFR response would be malformed and could
            // cause slave servers to end up with empty or corrupt zones.
            // Instead of proceeding with a non-compliant response, we MUST fail and let
            // the caller fallback to AXFR which is always safe.
            if (oldSoa == null)
            {
                return IxfrBuildResult.Failed($"Missing SOA record for FromSerial {diff.FromSerial} - cannot build RFC 1995-compliant IXFR response");
            }
            if (newSoa == null)
            {
                return IxfrBuildResult.Failed($"Missing SOA record for ToSerial {diff.ToSerial} - cannot build RFC 1995-compliant IXFR response");
            }

            // Send old SOA (required by RFC 1995 before deletions)
            var oldSoaCompression = new Dictionary<string, int>();
            var oldSoaMessage = BuildSoaMessage(oldSoa, queryId, originalQuestion, oldSoaCompression, isFirst: false);
            messages.Add(oldSoaMessage);

            // Send deleted records (excluding SOA, as it was already sent)
            foreach (var deletedRecord in diff.DeletedRecords)
            {
                if (deletedRecord.RecordType != DnsClient.Protocol.ResourceRecordType.SOA)
                {
                    var recordCompression = new Dictionary<string, int>();
                    var recordMessage = BuildRecordMessage(deletedRecord, queryId, originalQuestion, recordCompression);
                    messages.Add(recordMessage);
                }
            }

            // Send new SOA (required by RFC 1995 before additions)
            var newSoaCompression = new Dictionary<string, int>();
            var newSoaMessage = BuildSoaMessage(newSoa, queryId, originalQuestion, newSoaCompression, isFirst: false);
            messages.Add(newSoaMessage);

            // Send added records (excluding SOA, as it was already sent)
            foreach (var addedRecord in diff.AddedRecords)
            {
                if (addedRecord.RecordType != DnsClient.Protocol.ResourceRecordType.SOA)
                {
                    var recordCompression = new Dictionary<string, int>();
                    var recordMessage = BuildRecordMessage(addedRecord, queryId, originalQuestion, recordCompression);
                    messages.Add(recordMessage);
                }
            }
        }

        // Send final current SOA
        var finalSoaCompression = new Dictionary<string, int>();
        var finalSoaMessage = BuildSoaMessage(currentSoa, queryId, originalQuestion, finalSoaCompression, isFirst: false);
        messages.Add(finalSoaMessage);

        return IxfrBuildResult.Succeeded(messages);
    }

    /// <summary>
    /// Builds a minimal IXFR response when serials match (no changes).
    /// Returns only the current SOA record.
    /// </summary>
    public static byte[] BuildNoChangeResponse(
        FilteredRecord soa,
        ushort queryId,
        DnsQuestion question)
    {
        if (soa == null)
            throw new ArgumentNullException(nameof(soa));
        if (question == null)
            throw new ArgumentNullException(nameof(question));

        var nameCompression = new Dictionary<string, int>();

        return BuildSoaMessage(soa, queryId, question, nameCompression, isFirst: true);
    }

    /// <summary>
    /// Builds a DNS message containing a SOA record for IXFR response.
    /// </summary>
    private static byte[] BuildSoaMessage(
        FilteredRecord soaRecord,
        ushort queryId,
        DnsQuestion question,
        Dictionary<string, int> nameCompression,
        bool isFirst)
    {
        var data = new List<byte>();

        // Header
        DnsMessageParser.WriteUInt16(data, queryId);
        
        // Flags: Response, Authoritative, NoError
        // For IXFR, we use the same flags as AXFR
        var flags = 0x8500; // Response (0x8000) + Authoritative (0x0400) + NoError (0x0000)
        DnsMessageParser.WriteUInt16(data, (ushort)flags);

        // Question count: 1 for IXFR queries
        DnsMessageParser.WriteUInt16(data, 1);

        // Answer count: 1 (the SOA record)
        DnsMessageParser.WriteUInt16(data, 1);

        // Authority count: 0
        DnsMessageParser.WriteUInt16(data, 0);

        // Additional count: 0
        DnsMessageParser.WriteUInt16(data, 0);

        // Question section: echo back the IXFR query exactly as received (RFC 1995 requirement)
        var questionName = question.Name;
        // Normalize zone name for compression dictionary (always with trailing dot for consistency)
        // WriteDomainName produces the same bytes for "zone" and "zone.", so we normalize to always have trailing dot
        var normalizedZoneName = questionName.EndsWith('.') ? questionName : $"{questionName}.";
        var questionStart = data.Count;
        // Write question name exactly as received (RFC 1995 requires exact match)
        // Use the original question.Name to ensure byte-for-byte match
        DnsMessageParser.WriteDomainName(data, questionName);
        // Store compression pointer using normalized name (with trailing dot) for consistency
        // This matches what WriteRecordWithCompression expects when looking up zoneName.ToLowerInvariant()
        // Store both with and without trailing dot to handle all cases
        var normalizedKey = normalizedZoneName.ToLowerInvariant();
        nameCompression[normalizedKey] = questionStart;
        // Also store without trailing dot for lookup flexibility (WriteDomainName produces same bytes)
        var normalizedKeyNoDot = questionName.TrimEnd('.').ToLowerInvariant() + ".";
        if (normalizedKeyNoDot != normalizedKey)
        {
            nameCompression[normalizedKeyNoDot] = questionStart;
        }
        DnsMessageParser.WriteUInt16(data, (ushort)question.QueryType); // Use exact query type from request
        DnsMessageParser.WriteUInt16(data, (ushort)question.QueryClass); // Use exact query class from request

        // Answer section: SOA record
        WriteRecordWithCompression(data, soaRecord, nameCompression, normalizedZoneName);

        return data.ToArray();
    }

    /// <summary>
    /// Builds a DNS message containing a single record for IXFR response.
    /// </summary>
    private static byte[] BuildRecordMessage(
        FilteredRecord record,
        ushort queryId,
        DnsQuestion question,
        Dictionary<string, int> nameCompression)
    {
        var data = new List<byte>();

        // Header
        DnsMessageParser.WriteUInt16(data, queryId);
        var flags = 0x8500; // Response, Authoritative, NoError
        DnsMessageParser.WriteUInt16(data, (ushort)flags);

        // Question count: 1
        DnsMessageParser.WriteUInt16(data, 1);

        // Answer count: 1
        DnsMessageParser.WriteUInt16(data, 1);

        // Authority count: 0
        DnsMessageParser.WriteUInt16(data, 0);

        // Additional count: 0
        DnsMessageParser.WriteUInt16(data, 0);

        // Question section: echo back IXFR query exactly as received (RFC 1995 requirement)
        var questionName = question.Name;
        // Normalize zone name for compression dictionary (always with trailing dot for consistency)
        var normalizedZoneName = questionName.EndsWith('.') ? questionName : $"{questionName}.";
        var questionStart = data.Count;
        // Write question name exactly as received (RFC 1995 requires exact match)
        DnsMessageParser.WriteDomainName(data, questionName);
        // Store compression pointer for zone name (always store, even if already exists, to ensure consistency)
        // This ensures compression works correctly when record names match the zone name
        // Store both with and without trailing dot to handle all cases
        var normalizedKey = normalizedZoneName.ToLowerInvariant();
        nameCompression[normalizedKey] = questionStart;
        // Also store without trailing dot for lookup flexibility (WriteDomainName produces same bytes)
        var normalizedKeyNoDot = questionName.TrimEnd('.').ToLowerInvariant() + ".";
        if (normalizedKeyNoDot != normalizedKey)
        {
            nameCompression[normalizedKeyNoDot] = questionStart;
        }
        DnsMessageParser.WriteUInt16(data, (ushort)question.QueryType); // Use exact query type from request
        DnsMessageParser.WriteUInt16(data, (ushort)question.QueryClass); // Use exact query class from request

        // Answer section: the record
        WriteRecordWithCompression(data, record, nameCompression, normalizedZoneName);

        return data.ToArray();
    }

    /// <summary>
    /// Writes a record with name compression support.
    /// </summary>
    private static void WriteRecordWithCompression(
        List<byte> data,
        FilteredRecord record,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        // Write domain name with compression
        var recordName = record.DomainName.TrimEnd('.');
        var normalizedRecordName = recordName.ToLowerInvariant();
        // Normalize zone name for consistent lookup (ensure trailing dot matches storage)
        var normalizedZoneNameForLookup = zoneName.EndsWith('.') ? zoneName.ToLowerInvariant() : $"{zoneName}.".ToLowerInvariant();
        var normalizedZoneNameForCompare = zoneName.TrimEnd('.').ToLowerInvariant();

        // Check if we can compress: if record name equals zone name, use compression pointer
        // DNS compression pointers can point anywhere in the message (RFC 1035) and must be < 16384 (14 bits)
        if (normalizedRecordName == normalizedZoneNameForCompare && nameCompression.ContainsKey(normalizedZoneNameForLookup))
        {
            var offset = nameCompression[normalizedZoneNameForLookup];
            // Validate offset: must be >= 12 (DNS header size) and < 16384 (max compression pointer value)
            // Also validate that offset points backward (offset < current position in the message being built)
            if (offset >= 12 && offset < 16384 && offset < data.Count)
            {
                DnsMessageParser.WriteUInt16(data, (ushort)(0xC000 | offset));
            }
            else
            {
                // Offset invalid, write full name instead
                DnsMessageParser.WriteDomainName(data, record.DomainName);
            }
        }
        else
        {
            DnsMessageParser.WriteDomainName(data, record.DomainName);
        }

        // Write type and class
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordType);
        DnsMessageParser.WriteUInt16(data, (ushort)record.RecordClass);

        // Write TTL
        DnsMessageParser.WriteUInt32(data, (uint)record.TimeToLive);

        // Write RDATA
        // CRITICAL FIX: Don't use compression in RDATA for IXFR responses to avoid "malformed data" errors
        // Compression in RDATA is optional and some DNS servers (like Knot DNS) are strict about validation
        // We'll serialize RDATA without compression to ensure compatibility
        var rdata = SerializeRdataWithoutCompression(record);
        DnsMessageParser.WriteUInt16(data, (ushort)rdata.Length);
        data.AddRange(rdata);
    }

    /// <summary>
    /// Serializes RDATA for a record with compression support.
    /// </summary>
    private static byte[] SerializeRdata(
        FilteredRecord record,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        if (record.SoaData != null)
        {
            return SerializeSoaRdata(record.SoaData, nameCompression, zoneName);
        }
        
        if (record.NsName != null)
        {
            return SerializeNsRdata(record.NsName, nameCompression, zoneName);
        }
        
        if (record.OriginalRecord != null)
        {
            // Use DnsRecordBuilder's serialization logic
            return DnsRecordBuilder.SerializeRdataForRecord(record, nameCompression, zoneName);
        }

        // Fallback: return empty if no RDATA can be serialized
        return Array.Empty<byte>();
    }

    /// <summary>
    /// Serializes RDATA for a record without compression (for IXFR responses to avoid malformed data errors).
    /// </summary>
    private static byte[] SerializeRdataWithoutCompression(FilteredRecord record)
    {
        if (record.RawRData is { Length: > 0 })
        {
            return record.RawRData.ToArray();
        }

        if (record.SoaData != null)
        {
            return SerializeSoaRdataWithoutCompression(record.SoaData);
        }
        
        if (record.NsName != null)
        {
            return SerializeNsRdataWithoutCompression(record.NsName);
        }
        
        if (record.OriginalRecord != null)
        {
            // Serialize without compression for IXFR responses
            // Use type-specific serialization without compression
            var data = new List<byte>();
            switch (record.OriginalRecord)
            {
                case DnsClient.Protocol.SoaRecord soa:
                    DnsMessageParser.WriteDomainName(data, soa.MName.Value);
                    DnsMessageParser.WriteDomainName(data, soa.RName.Value);
                    DnsMessageParser.WriteUInt32(data, (uint)soa.Serial);
                    DnsMessageParser.WriteUInt32(data, (uint)soa.Refresh);
                    DnsMessageParser.WriteUInt32(data, (uint)soa.Retry);
                    DnsMessageParser.WriteUInt32(data, (uint)soa.Expire);
                    DnsMessageParser.WriteUInt32(data, (uint)soa.Minimum);
                    return data.ToArray();
                    
                case DnsClient.Protocol.NsRecord ns:
                    DnsMessageParser.WriteDomainName(data, ns.NSDName.Value);
                    return data.ToArray();
                    
                case DnsClient.Protocol.ARecord a:
                    data.AddRange(a.Address.GetAddressBytes());
                    return data.ToArray();
                    
                case DnsClient.Protocol.AaaaRecord aaaa:
                    data.AddRange(aaaa.Address.GetAddressBytes());
                    return data.ToArray();
                    
                case DnsClient.Protocol.MxRecord mx:
                    DnsMessageParser.WriteUInt16(data, (ushort)mx.Preference);
                    DnsMessageParser.WriteDomainName(data, mx.Exchange.Value);
                    return data.ToArray();
                    
                case DnsClient.Protocol.CNameRecord cname:
                    DnsMessageParser.WriteDomainName(data, cname.CanonicalName.Value);
                    return data.ToArray();
                    
                case DnsClient.Protocol.SrvRecord srv:
                    DnsMessageParser.WriteUInt16(data, (ushort)srv.Priority);
                    DnsMessageParser.WriteUInt16(data, (ushort)srv.Weight);
                    DnsMessageParser.WriteUInt16(data, (ushort)srv.Port);
                    DnsMessageParser.WriteDomainName(data, srv.Target.Value);
                    return data.ToArray();
                    
                case DnsClient.Protocol.PtrRecord ptr:
                    DnsMessageParser.WriteDomainName(data, ptr.PtrDomainName.Value);
                    return data.ToArray();
                    
                case DnsClient.Protocol.TxtRecord txt:
                    // TXT records: concatenate all text strings, each prefixed with length
                    foreach (var text in txt.Text)
                    {
                        var bytes = System.Text.Encoding.UTF8.GetBytes(text);
                        data.Add((byte)bytes.Length);
                        data.AddRange(bytes);
                    }
                    return data.ToArray();
                    
                case DnsClient.Protocol.CaaRecord caa:
                    // RFC 6844: CAA record format
                    data.Add((byte)caa.Flags);
                    var tagBytes = System.Text.Encoding.ASCII.GetBytes(caa.Tag);
                    data.Add((byte)tagBytes.Length);
                    data.AddRange(tagBytes);
                    var valueBytes = System.Text.Encoding.UTF8.GetBytes(caa.Value);
                    data.Add((byte)valueBytes.Length);
                    data.AddRange(valueBytes);
                    return data.ToArray();
                    
                default:
                    // For unknown types, return empty (shouldn't happen in practice)
                    return Array.Empty<byte>();
            }
        }

        // Fallback: return empty if no RDATA can be serialized
        return Array.Empty<byte>();
    }

    /// <summary>
    /// Serializes SOA RDATA without compression.
    /// </summary>
    private static byte[] SerializeSoaRdataWithoutCompression(SoaRecordData soa)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, soa.MName);
        DnsMessageParser.WriteDomainName(data, soa.RName);
        DnsMessageParser.WriteUInt32(data, soa.Serial);
        DnsMessageParser.WriteUInt32(data, soa.Refresh);
        DnsMessageParser.WriteUInt32(data, soa.Retry);
        DnsMessageParser.WriteUInt32(data, soa.Expire);
        DnsMessageParser.WriteUInt32(data, soa.Minimum);
        return data.ToArray();
    }

    /// <summary>
    /// Serializes NS RDATA without compression.
    /// </summary>
    private static byte[] SerializeNsRdataWithoutCompression(string nsName)
    {
        var data = new List<byte>();
        DnsMessageParser.WriteDomainName(data, nsName);
        return data.ToArray();
    }

    /// <summary>
    /// Serializes SOA RDATA with compression support.
    /// </summary>
    private static byte[] SerializeSoaRdata(
        SoaRecordData soa,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, soa.MName, nameCompression, zoneName);
        WriteDomainNameWithCompression(data, soa.RName, nameCompression, zoneName);
        DnsMessageParser.WriteUInt32(data, soa.Serial);
        DnsMessageParser.WriteUInt32(data, soa.Refresh);
        DnsMessageParser.WriteUInt32(data, soa.Retry);
        DnsMessageParser.WriteUInt32(data, soa.Expire);
        DnsMessageParser.WriteUInt32(data, soa.Minimum);
        return data.ToArray();
    }

    /// <summary>
    /// Serializes NS RDATA with compression support.
    /// </summary>
    private static byte[] SerializeNsRdata(
        string nsName,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var data = new List<byte>();
        WriteDomainNameWithCompression(data, nsName, nameCompression, zoneName);
        return data.ToArray();
    }

    /// <summary>
    /// Writes a domain name with compression support.
    /// </summary>
    private static void WriteDomainNameWithCompression(
        List<byte> data,
        string name,
        Dictionary<string, int> nameCompression,
        string zoneName)
    {
        var normalizedName = name.TrimEnd('.').ToLowerInvariant();
        var normalizedZoneNameForCompare = zoneName.TrimEnd('.').ToLowerInvariant();
        // Normalize zone name for consistent lookup (ensure trailing dot matches storage)
        var normalizedZoneNameForLookup = zoneName.EndsWith('.') ? zoneName.ToLowerInvariant() : $"{zoneName}.".ToLowerInvariant();

        // Check if this name matches the zone name and we have a compression pointer
        // DNS compression pointers can point anywhere in the message (RFC 1035) and must be < 16384 (14 bits)
        if (normalizedName == normalizedZoneNameForCompare && nameCompression.ContainsKey(normalizedZoneNameForLookup))
        {
            var offset = nameCompression[normalizedZoneNameForLookup];
            // Validate offset: must be >= 12 (DNS header size) and < 16384 (max compression pointer value)
            // Note: We don't check offset < data.Count here because when called from RDATA serialization,
            // data is the RDATA buffer, not the full message. Compression pointers can reference names
            // anywhere in the full DNS message.
            // CRITICAL: Compression pointers must point to a valid location in the message where a domain name starts.
            // The offset should point to the first byte of a domain name (the length byte of the first label).
            if (offset >= 12 && offset < 16384)
            {
                // Write compression pointer (2 bytes: 0xC000 | offset)
                DnsMessageParser.WriteUInt16(data, (ushort)(0xC000 | offset));
                return;
            }
        }

        // Write full name (no compression for other names)
        DnsMessageParser.WriteDomainName(data, name);
    }
}
