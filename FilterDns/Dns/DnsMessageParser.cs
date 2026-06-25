using System.Net;
using System.Text;
using FilterDns.Config;

namespace FilterDns.Dns;

public class DnsMessage
{
    public ushort Id { get; set; }
    public bool IsQuery { get; set; }
    public DnsOpCode OpCode { get; set; }
    public bool AuthoritativeAnswer { get; set; }
    public bool Truncated { get; set; }
    public bool RecursionDesired { get; set; }
    public bool RecursionAvailable { get; set; }
    public DnsResponseCode ResponseCode { get; set; }
    public List<DnsQuestion> Questions { get; set; } = new();
    public List<SimpleDnsResourceRecord> Authority { get; set; } = new();
}

public class DnsQuestion
{
    public string Name { get; set; } = string.Empty;
    public DnsQueryType QueryType { get; set; }
    public DnsQueryClass QueryClass { get; set; }
}

public enum DnsOpCode
{
    Query = 0,
    Notify = 4,
    Update = 5
}

public enum DnsQueryType
{
    A = 1,
    NS = 2,
    SOA = 6,
    AAAA = 28,
    AXFR = 252,
    IXFR = 251
}

public enum DnsQueryClass
{
    IN = 1
}

public enum DnsResponseCode
{
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NXDomain = 3,
    NotImp = 4,
    Refused = 5
}

public static class DnsMessageParser
{
    // Default security limits (used when SecurityConfig is null or hardening is disabled)
    private const int DefaultMaxCompressionPointerDepth = 10;
    private const int DefaultMaxDomainNameLength = 255;
    private const int DefaultMaxLabelLength = 63;
    private const int DefaultMaxMessageCounts = 100;

    /// <summary>
    /// Parses a DNS message with security hardening enabled by default.
    /// </summary>
    public static DnsMessage Parse(byte[] data)
    {
        return Parse(data, null);
    }

    /// <summary>
    /// Parses a DNS message with configurable security limits.
    /// </summary>
    /// <param name="data">The DNS message bytes</param>
    /// <param name="securityConfig">Security configuration. If null, uses defaults with hardening enabled.</param>
    /// <returns>Parsed DNS message</returns>
    /// <exception cref="FormatException">Thrown when message is malformed and security hardening is enabled</exception>
    public static DnsMessage Parse(byte[] data, SecurityConfig? securityConfig)
    {
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;
        var maxMessageCounts = securityConfig?.MaxMessageCounts ?? DefaultMaxMessageCounts;

        try
        {
            var message = new DnsMessage();
            var offset = 0;

            // Validate buffer is not empty
            if (data == null || data.Length == 0)
            {
                throw new FormatException("DNS message buffer is empty");
            }

            // Parse header with bounds checking
            if (!ValidateBounds(data, offset, 12, hardeningEnabled))
            {
                throw new FormatException("DNS message header too short");
            }

            message.Id = ReadUInt16(data, ref offset, hardeningEnabled);
            var flags = ReadUInt16(data, ref offset, hardeningEnabled);
            message.IsQuery = (flags & 0x8000) == 0;
            message.OpCode = (DnsOpCode)((flags >> 11) & 0x0F);
            message.AuthoritativeAnswer = (flags & 0x0400) != 0;
            message.Truncated = (flags & 0x0200) != 0;
            message.RecursionDesired = (flags & 0x0100) != 0;
            message.RecursionAvailable = (flags & 0x0080) != 0;
            message.ResponseCode = (DnsResponseCode)(flags & 0x000F);

            var qdCount = ReadUInt16(data, ref offset, hardeningEnabled);
            var anCount = ReadUInt16(data, ref offset, hardeningEnabled);
            var nsCount = ReadUInt16(data, ref offset, hardeningEnabled);
            var arCount = ReadUInt16(data, ref offset, hardeningEnabled);

            // Validate counts are reasonable (security hardening)
            if (hardeningEnabled)
            {
                if (qdCount > maxMessageCounts)
                    throw new FormatException($"Question count ({qdCount}) exceeds maximum ({maxMessageCounts})");
                if (anCount > maxMessageCounts)
                    throw new FormatException($"Answer count ({anCount}) exceeds maximum ({maxMessageCounts})");
                if (nsCount > maxMessageCounts)
                    throw new FormatException($"Authority count ({nsCount}) exceeds maximum ({maxMessageCounts})");
                if (arCount > maxMessageCounts)
                    throw new FormatException($"Additional count ({arCount}) exceeds maximum ({maxMessageCounts})");
            }

            // Parse questions
            for (int i = 0; i < qdCount; i++)
            {
                var question = new DnsQuestion
                {
                    Name = ReadDomainName(data, ref offset, securityConfig),
                    QueryType = (DnsQueryType)ReadUInt16(data, ref offset, hardeningEnabled),
                    QueryClass = (DnsQueryClass)ReadUInt16(data, ref offset, hardeningEnabled)
                };
                message.Questions.Add(question);
            }

            // Parse answer section (skip for now, not needed for IXFR requests)
            for (int i = 0; i < anCount; i++)
            {
                SkipResourceRecord(data, ref offset, securityConfig);
            }

            // Parse authority section (contains SOA for IXFR requests)
            // For IXFR requests, we MUST parse the authority section SOA to extract client serial
            // Be more lenient here - if a record fails to parse, skip it but continue
            // For IXFR, we need to be especially lenient to allow serial extraction via fallback
            var isIxfrRequest = message.Questions.Any(q => q.QueryType == DnsQueryType.IXFR);
            
            for (int i = 0; i < nsCount; i++)
            {
                var recordStartOffset = offset;
                try
                {
                    var record = ReadResourceRecord(data, ref offset, securityConfig);
                    if (record != null)
                    {
                        message.Authority.Add(record);
                    }
                    // If ReadResourceRecord returns null, offset should still have been advanced
                    // If not, we'd get stuck in a loop, but ReadResourceRecord should always advance offset
                }
                catch (FormatException) when (isIxfrRequest)
                {
                    // For IXFR requests, if parsing fails, use SkipResourceRecord to properly advance offset
                    // This ensures the raw message buffer will be parseable by the fallback extraction
                    try
                    {
                        // Reset offset to start of this record and skip it properly
                        offset = recordStartOffset;
                        SkipResourceRecord(data, ref offset, securityConfig);
                    }
                    catch
                    {
                        // If SkipResourceRecord also fails, try manual recovery
                        if (offset == recordStartOffset && offset < data.Length)
                        {
                            // Try to skip domain name at least
                            offset = recordStartOffset + 1;
                        }
                        else
                        {
                            // Offset was advanced, break to avoid issues
                            break;
                        }
                    }
                }
                catch (FormatException)
                {
                    // For non-IXFR, use simpler recovery
                    try
                    {
                        if (offset == recordStartOffset && offset < data.Length)
                        {
                            offset = recordStartOffset + 1;
                        }
                    }
                    catch
                    {
                        break;
                    }
                }
            }

            // Parse additional section (skip for now)
            for (int i = 0; i < arCount; i++)
            {
                SkipResourceRecord(data, ref offset, securityConfig);
            }

            return message;
        }
        catch (IndexOutOfRangeException)
        {
            // Don't include inner exception to avoid exposing stack traces
            throw new FormatException("DNS message parsing failed: buffer overflow");
        }
        catch (FormatException)
        {
            throw; // Re-throw FormatException as-is (already sanitized)
        }
        catch (Exception)
        {
            // Don't include inner exception to avoid exposing internal details
            throw new FormatException("DNS message parsing failed: unexpected error");
        }
    }

    public static byte[] BuildResponse(DnsMessage request, DnsResponseCode responseCode)
    {
        var data = new List<byte>();

        // Header
        WriteUInt16(data, request.Id);
        var flags = 0x8000; // Response
        flags |= ((int)request.OpCode << 11);
        flags |= (int)responseCode;
        WriteUInt16(data, (ushort)flags);
        WriteUInt16(data, (ushort)request.Questions.Count); // QDCOUNT
        WriteUInt16(data, 0); // ANCOUNT
        WriteUInt16(data, 0); // NSCOUNT
        WriteUInt16(data, 0); // ARCOUNT

        // Questions (echo back)
        foreach (var question in request.Questions)
        {
            WriteDomainName(data, question.Name);
            WriteUInt16(data, (ushort)question.QueryType);
            WriteUInt16(data, (ushort)question.QueryClass);
        }

        return data.ToArray();
    }

    /// <summary>
    /// Validates that there are enough bytes remaining in the buffer.
    /// </summary>
    private static bool ValidateBounds(byte[] data, int offset, int requiredBytes, bool throwOnError)
    {
        if (offset < 0 || offset + requiredBytes > data.Length)
        {
            if (throwOnError)
            {
                throw new FormatException($"Buffer bounds violation: offset={offset}, required={requiredBytes}, length={data.Length}");
            }
            return false;
        }
        return true;
    }

    private static ushort ReadUInt16(byte[] data, ref int offset)
    {
        return ReadUInt16(data, ref offset, true);
    }

    private static ushort ReadUInt16(byte[] data, ref int offset, bool validateBounds)
    {
        if (validateBounds && !ValidateBounds(data, offset, 2, true))
        {
            throw new FormatException("Cannot read UInt16: insufficient bytes");
        }

        var value = (ushort)((data[offset] << 8) | data[offset + 1]);
        offset += 2;
        return value;
    }

    public static void WriteUInt16(List<byte> data, ushort value)
    {
        data.Add((byte)(value >> 8));
        data.Add((byte)(value & 0xFF));
    }

    private static string ReadDomainName(byte[] data, ref int offset)
    {
        return ReadDomainName(data, ref offset, null);
    }

    private static string ReadDomainName(byte[] data, ref int offset, SecurityConfig? securityConfig)
    {
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;
        var maxCompressionDepth = securityConfig?.MaxCompressionPointerDepth ?? DefaultMaxCompressionPointerDepth;
        var maxDomainNameLength = securityConfig?.MaxDomainNameLength ?? DefaultMaxDomainNameLength;
        var maxLabelLength = securityConfig?.MaxLabelLength ?? DefaultMaxLabelLength;

        var parts = new List<string>();
        var startOffset = offset;
        var jumped = false;
        var jumpOffset = 0;
        var visitedOffsets = new HashSet<int>(); // Track visited offsets to detect loops
        int compressionDepth = 0;
        int totalNameLength = 0;

        while (offset < data.Length)
        {
            // Bounds check before reading length byte
            if (hardeningEnabled && !ValidateBounds(data, offset, 1, false))
            {
                throw new FormatException("Domain name parsing failed: buffer overflow while reading length");
            }

            var length = data[offset++];

            if (length == 0)
                break;

            if ((length & 0xC0) == 0xC0)
            {
                // Compression pointer
                if (hardeningEnabled)
                {
                    compressionDepth++;
                    if (compressionDepth > maxCompressionDepth)
                    {
                        throw new FormatException($"Compression pointer depth ({compressionDepth}) exceeds maximum ({maxCompressionDepth})");
                    }

                    // Check bounds before reading second byte of compression pointer
                    if (!ValidateBounds(data, offset, 1, false))
                    {
                        throw new FormatException("Domain name parsing failed: buffer overflow while reading compression pointer");
                    }

                    if (!jumped)
                    {
                        jumpOffset = offset + 1;
                        jumped = true;
                    }

                    var newOffset = ((length & 0x3F) << 8) | data[offset];
                    
                    // Check for compression pointer loops
                    if (visitedOffsets.Contains(newOffset))
                    {
                        throw new FormatException($"Compression pointer loop detected at offset {newOffset}");
                    }
                    
                    visitedOffsets.Add(newOffset);
                    
                    // Validate compression pointer doesn't point outside buffer
                    if (newOffset >= data.Length || newOffset < 0)
                    {
                        throw new FormatException($"Compression pointer points to invalid offset: {newOffset}");
                    }
                    
                    offset = newOffset;
                }
                else
                {
                    // Legacy behavior without hardening
                    if (!jumped)
                    {
                        jumpOffset = offset + 1;
                        jumped = true;
                    }
                    if (!ValidateBounds(data, offset, 1, false))
                    {
                        break; // Silent failure in legacy mode
                    }
                    offset = ((length & 0x3F) << 8) | data[offset];
                }
                continue;
            }

            // Validate label length
            if (hardeningEnabled && length > maxLabelLength)
            {
                throw new FormatException($"Label length ({length}) exceeds maximum ({maxLabelLength})");
            }

            if (length > 63)
                break;

            // Bounds check before reading label
            if (hardeningEnabled && !ValidateBounds(data, offset, length, false))
            {
                throw new FormatException("Domain name parsing failed: buffer overflow while reading label");
            }

            var part = Encoding.UTF8.GetString(data, offset, length);
            parts.Add(part);
            totalNameLength += length + 1; // +1 for the dot separator

            // Validate total domain name length
            if (hardeningEnabled && totalNameLength > maxDomainNameLength)
            {
                throw new FormatException($"Domain name length ({totalNameLength}) exceeds maximum ({maxDomainNameLength})");
            }

            offset += length;
        }

        if (jumped)
        {
            offset = jumpOffset;
        }

        var domainName = string.Join(".", parts);
        
        // Final validation of total length
        if (hardeningEnabled && domainName.Length > maxDomainNameLength)
        {
            throw new FormatException($"Domain name length ({domainName.Length}) exceeds maximum ({maxDomainNameLength})");
        }

        return domainName;
    }

    public static void WriteDomainName(List<byte> data, string name)
    {
        var parts = name.Split('.');
        foreach (var part in parts)
        {
            if (string.IsNullOrEmpty(part)) continue;
            data.Add((byte)part.Length);
            data.AddRange(Encoding.UTF8.GetBytes(part));
        }
        data.Add(0); // Terminator
    }

    public static void WriteUInt32(List<byte> data, uint value)
    {
        data.Add((byte)(value >> 24));
        data.Add((byte)(value >> 16));
        data.Add((byte)(value >> 8));
        data.Add((byte)(value & 0xFF));
    }

    /// <summary>
    /// Builds a DNS NOTIFY message to send to a slave server.
    /// According to RFC 1996, NOTIFY messages must have RD bit set to 0 and other
    /// unspecified fields set to binary zero. Implementations must ignore messages
    /// that don't comply with this requirement.
    /// </summary>
    /// <param name="zoneName">The zone name to notify about</param>
    /// <param name="messageId">The message ID (should be random)</param>
    /// <returns>Raw DNS NOTIFY message bytes</returns>
    public static byte[] BuildNotify(string zoneName, ushort messageId)
    {
        var data = new List<byte>();

        // Header
        WriteUInt16(data, messageId);
        // Flags: Query (0x0000), OpCode = NOTIFY (4 << 11 = 0x2000)
        // RFC 1996: RD bit MUST be 0, all unspecified fields must be binary zero
        var flags = 0x0000; // Query (not response), RD=0, RA=0, etc.
        flags |= ((int)DnsOpCode.Notify << 11); // NOTIFY opcode (bits 11-14)
        // Note: RD bit (bit 8) is explicitly set to 0, as required by RFC 1996
        WriteUInt16(data, (ushort)flags);
        WriteUInt16(data, 1); // QDCOUNT = 1
        WriteUInt16(data, 0); // ANCOUNT = 0
        WriteUInt16(data, 0); // NSCOUNT = 0
        WriteUInt16(data, 0); // ARCOUNT = 0

        // Question: SOA query for the zone
        var normalizedZoneName = zoneName.EndsWith('.') ? zoneName : $"{zoneName}.";
        WriteDomainName(data, normalizedZoneName);
        WriteUInt16(data, (ushort)DnsQueryType.SOA); // Query type SOA
        WriteUInt16(data, (ushort)DnsQueryClass.IN); // Class IN

        return data.ToArray();
    }

    /// <summary>
    /// Extracts the client's current serial number from an IXFR request's authority section.
    /// According to RFC 1995, IXFR requests include the client's SOA record in the authority section.
    /// </summary>
    /// <param name="request">The IXFR request message</param>
    /// <param name="rawMessage">Optional raw message bytes for fallback extraction if parsing failed</param>
    /// <returns>The client's serial number, or null if not found or not an IXFR request</returns>
    public static uint? ExtractIxfrClientSerial(DnsMessage request, byte[]? rawMessage = null)
    {
        // Check if this is an IXFR request
        var isIxfr = request.Questions.Any(q => q.QueryType == DnsQueryType.IXFR);
        if (!isIxfr)
        {
            return null;
        }

        // Look for SOA record in authority section
        // Check both enum comparison and numeric value (type 6 = SOA)
        // Also accept type 251 (IXFR) which some implementations incorrectly use in authority section
        foreach (var record in request.Authority)
        {
            // Check if it's SOA by enum, numeric value (6), or incorrectly typed as IXFR (251)
            var recordTypeInt = (int)record.RecordType;
            bool isSoa = record.RecordType == DnsClient.Protocol.ResourceRecordType.SOA || 
                        recordTypeInt == 6 || 
                        recordTypeInt == 251; // Some clients incorrectly use IXFR type in authority
            
            if (isSoa)
            {
                // Check if RDATA exists and has reasonable size for SOA (at least 4 bytes for serial)
                if (record.Rdata == null || record.Rdata.Length < 4)
                {
                    // RDATA is missing or too short - fall through to raw byte extraction
                    continue;
                }
                
                // Try with hardening enabled first (default)
                var serial = ExtractSerialFromSoaRecord(record, null);
                if (serial != null)
                {
                    return serial;
                }
                
                // If that failed, try with hardening disabled (more lenient)
                // This handles cases where validation is too strict for legitimate IXFR requests
                var lenientConfig = new SecurityConfig { SecurityHardeningEnabled = false };
                serial = ExtractSerialFromSoaRecord(record, lenientConfig);
                if (serial != null)
                {
                    return serial;
                }
                
                // If serial extraction failed even with lenient config, fall through to raw byte extraction fallback
                // This can happen if RDATA is corrupted or in an unexpected format
            }
        }

        // Fallback: if authority section is empty or SOA parsing failed, try to extract from raw bytes
        // Always try fallback if we didn't successfully extract serial from parsed Authority
        if (rawMessage != null && rawMessage.Length >= 12)
        {
            try
            {
                // Parse header to get counts
                var qdCount = (ushort)((rawMessage[4] << 8) | rawMessage[5]);
                var anCount = (ushort)((rawMessage[6] << 8) | rawMessage[7]);
                var nsCount = (ushort)((rawMessage[10] << 8) | rawMessage[11]);
                
                if (nsCount > 0)
                {
                    // Skip question section to find authority section
                    int offset = 12;
                    
                    // Skip questions
                    for (int i = 0; i < qdCount && offset < rawMessage.Length; i++)
                    {
                        // Skip domain name
                        while (offset < rawMessage.Length && rawMessage[offset] != 0)
                        {
                            if ((rawMessage[offset] & 0xC0) == 0xC0)
                            {
                                offset += 2;
                                break;
                            }
                            var len = rawMessage[offset++];
                            if (len == 0) break;
                            if (offset + len > rawMessage.Length) break;
                            offset += len;
                        }
                        if (offset < rawMessage.Length && rawMessage[offset] == 0) offset++; // Skip terminator
                        if (offset + 4 > rawMessage.Length) break;
                        offset += 4; // Skip type and class
                    }
                    
                    // Skip answer section
                    for (int i = 0; i < anCount && offset < rawMessage.Length; i++)
                    {
                        // Skip domain name
                        while (offset < rawMessage.Length && rawMessage[offset] != 0)
                        {
                            if ((rawMessage[offset] & 0xC0) == 0xC0)
                            {
                                offset += 2;
                                break;
                            }
                            var len = rawMessage[offset++];
                            if (len == 0) break;
                            if (offset + len > rawMessage.Length) break;
                            offset += len;
                        }
                        if (offset < rawMessage.Length && rawMessage[offset] == 0) offset++;
                        if (offset + 10 >= rawMessage.Length) break;
                        var rdataLen = (ushort)((rawMessage[offset + 8] << 8) | rawMessage[offset + 9]);
                        offset += 10;
                        if (offset + rdataLen > rawMessage.Length) break;
                        offset += rdataLen;
                    }
                    
                    // Now at authority section - try to find SOA and extract serial
                    if (offset < rawMessage.Length)
                    {
                        // Save the start of authority section for domain name skipping
                        var authSectionStart = offset;
                        
                        // Skip domain name in authority record (may use compression)
                        // We need to advance past the domain name WITHOUT following compression pointers
                        // because compression pointers point to the name elsewhere, but we need to stay
                        // at the position right after the domain name field to read type/class/TTL
                        while (offset < rawMessage.Length && offset < authSectionStart + 255) // Max domain name length
                        {
                            if ((rawMessage[offset] & 0xC0) == 0xC0)
                            {
                                // Compression pointer - just skip past it (2 bytes) without following
                                // This keeps us at the correct position to read type/class/TTL
                                offset += 2;
                                break;
                            }
                            
                            var len = rawMessage[offset++];
                            if (len == 0) break; // End of domain name
                            if (len > 63) break; // Invalid label length
                            if (offset + len > rawMessage.Length) break;
                            offset += len;
                        }
                        
                        // Now offset points to the type field (2 bytes) + class (2 bytes) + TTL (4 bytes) + RDATA length (2 bytes)
                        // Check if type is SOA (6) or incorrectly typed as IXFR (251)
                        if (offset + 10 <= rawMessage.Length)
                        {
                            var type = (ushort)((rawMessage[offset] << 8) | rawMessage[offset + 1]);
                            
                            // Accept SOA (6) or incorrectly typed IXFR (251) - both should have SOA RDATA format
                            if (type == 6 || type == 251) // SOA or incorrectly typed IXFR
                            {
                                // Read RDATA length before skipping (it's at offset + 8 and offset + 9)
                                var rdataLen = (ushort)((rawMessage[offset + 8] << 8) | rawMessage[offset + 9]);
                                offset += 10; // Skip type, class, TTL, RDATA length
                                
                                if (rdataLen >= 4 && offset + rdataLen <= rawMessage.Length)
                                {
                                    // Skip MNAME and RNAME to find SERIAL
                                    int rdataOffset = offset;
                                    int serialOffset = rdataOffset;
                                    
                                    // Skip MNAME (domain name, may use compression)
                                    var visitedRdataOffsets = new HashSet<int>();
                                    while (serialOffset < rawMessage.Length && serialOffset < offset + rdataLen && rawMessage[serialOffset] != 0)
                                    {
                                        if ((rawMessage[serialOffset] & 0xC0) == 0xC0)
                                        {
                                            // Compression pointer - follow it in the original message
                                            if (serialOffset + 1 >= rawMessage.Length) break;
                                            var compOffset = (ushort)(((rawMessage[serialOffset] & 0x3F) << 8) | rawMessage[serialOffset + 1]);
                                            if (compOffset >= rawMessage.Length) break;
                                            if (visitedRdataOffsets.Contains(compOffset)) break; // Loop detected
                                            visitedRdataOffsets.Add(compOffset);
                                            serialOffset = compOffset;
                                            continue;
                                        }
                                        var len = rawMessage[serialOffset++];
                                        if (len == 0) break;
                                        if (len > 63) break; // Invalid label length
                                        if (serialOffset + len > rawMessage.Length || serialOffset + len > offset + rdataLen) break;
                                        serialOffset += len;
                                    }
                                    if (serialOffset < rawMessage.Length && serialOffset < offset + rdataLen && rawMessage[serialOffset] == 0) serialOffset++;
                                    
                                    // Skip RNAME (domain name, may use compression)
                                    visitedRdataOffsets.Clear();
                                    while (serialOffset < rawMessage.Length && serialOffset < offset + rdataLen && rawMessage[serialOffset] != 0)
                                    {
                                        if ((rawMessage[serialOffset] & 0xC0) == 0xC0)
                                        {
                                            // Compression pointer - follow it in the original message
                                            if (serialOffset + 1 >= rawMessage.Length) break;
                                            var compOffset = (ushort)(((rawMessage[serialOffset] & 0x3F) << 8) | rawMessage[serialOffset + 1]);
                                            if (compOffset >= rawMessage.Length) break;
                                            if (visitedRdataOffsets.Contains(compOffset)) break; // Loop detected
                                            visitedRdataOffsets.Add(compOffset);
                                            serialOffset = compOffset;
                                            continue;
                                        }
                                        var len = rawMessage[serialOffset++];
                                        if (len == 0) break;
                                        if (len > 63) break; // Invalid label length
                                        if (serialOffset + len > rawMessage.Length || serialOffset + len > offset + rdataLen) break;
                                        serialOffset += len;
                                    }
                                    if (serialOffset < rawMessage.Length && serialOffset < offset + rdataLen && rawMessage[serialOffset] == 0) serialOffset++;
                                    
                                    // Read SERIAL (4 bytes)
                                    if (serialOffset + 4 <= rawMessage.Length && serialOffset + 4 <= offset + rdataLen)
                                    {
                                        var serial = (uint)((rawMessage[serialOffset] << 24) | 
                                                           (rawMessage[serialOffset + 1] << 16) | 
                                                           (rawMessage[serialOffset + 2] << 8) | 
                                                           rawMessage[serialOffset + 3]);
                                        return serial;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch
            {
                // Fallback extraction failed - return null (don't log to avoid spam)
                // The calling code will handle the null return appropriately
            }
        }

        return null;
    }

    /// <summary>
    /// Reads a resource record from the DNS message.
    /// </summary>
    private static SimpleDnsResourceRecord? ReadResourceRecord(byte[] data, ref int offset)
    {
        return ReadResourceRecord(data, ref offset, null);
    }

    private static SimpleDnsResourceRecord? ReadResourceRecord(byte[] data, ref int offset, SecurityConfig? securityConfig)
    {
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;

        if (offset >= data.Length)
            return null;

        var startOffset = offset;

        // Read domain name with security validation
        var name = ReadDomainName(data, ref offset, securityConfig);

        // Read type and class with bounds checking
        if (!ValidateBounds(data, offset, 4, hardeningEnabled))
        {
            if (hardeningEnabled)
                throw new FormatException("Resource record parsing failed: insufficient bytes for type and class");
            return null;
        }

        var type = ReadUInt16(data, ref offset, hardeningEnabled);
        var recordClass = ReadUInt16(data, ref offset, hardeningEnabled);

        // Read TTL
        if (!ValidateBounds(data, offset, 4, hardeningEnabled))
        {
            if (hardeningEnabled)
                throw new FormatException("Resource record parsing failed: insufficient bytes for TTL");
            return null;
        }
        var ttl = ReadUInt32(data, ref offset, hardeningEnabled);

        // Read RDATA length
        if (!ValidateBounds(data, offset, 2, hardeningEnabled))
        {
            if (hardeningEnabled)
                throw new FormatException("Resource record parsing failed: insufficient bytes for RDATA length");
            return null;
        }
        var rdataLength = ReadUInt16(data, ref offset, hardeningEnabled);

        // Validate RDATA length is reasonable (configurable maximum)
        var maxRdataLength = securityConfig?.MaxRdataLength ?? 65535;
        if (hardeningEnabled)
        {
            if (rdataLength > maxRdataLength)
            {
                throw new FormatException($"RDATA length ({rdataLength}) exceeds maximum ({maxRdataLength})");
            }
            // Be lenient: if RDATA length exceeds buffer, use what's available
            // This handles cases where messages might be partially corrupted but still parseable
        }

        // Store RDATA (use available bytes if length exceeds buffer)
        var actualRdataLength = Math.Min(rdataLength, data.Length - offset);
        var rdata = new byte[rdataLength]; // Allocate full size, but only copy what's available
        if (actualRdataLength > 0 && offset + actualRdataLength <= data.Length)
        {
            Array.Copy(data, offset, rdata, 0, actualRdataLength);
            offset += actualRdataLength;
            // If we didn't read the full RDATA, pad with zeros (or leave as-is)
            // The caller should handle partial RDATA gracefully
        }
        else if (rdataLength > 0)
        {
            // RDATA length specified but no bytes available - use empty RDATA
            // This is lenient handling for malformed messages
            offset = Math.Min(offset, data.Length);
        }
        else
        {
            // Zero-length RDATA - this is valid
            offset += rdataLength;
        }

        // Create a simple representation - for IXFR we mainly need SOA serial
        // Full parsing would require DnsClient library integration
        // We'll use a wrapper that implements the interface we need
        return new SimpleDnsResourceRecord(name, (DnsClient.Protocol.ResourceRecordType)type, (DnsClient.QueryClass)recordClass, (int)ttl, rdata);
    }

    /// <summary>
    /// Skips a resource record without parsing it.
    /// </summary>
    private static void SkipResourceRecord(byte[] data, ref int offset)
    {
        SkipResourceRecord(data, ref offset, null);
    }

    private static void SkipResourceRecord(byte[] data, ref int offset, SecurityConfig? securityConfig)
    {
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;

        if (offset >= data.Length)
            return;

        // Skip domain name (with security validation)
        ReadDomainName(data, ref offset, securityConfig);

        // Skip type, class, TTL (2 + 2 + 4 = 8 bytes)
        if (hardeningEnabled && !ValidateBounds(data, offset, 8, false))
        {
            throw new FormatException("SkipResourceRecord failed: insufficient bytes for type, class, and TTL");
        }

        if (offset + 8 <= data.Length)
        {
            offset += 8;
        }
        else
        {
            if (hardeningEnabled)
                throw new FormatException("SkipResourceRecord failed: buffer overflow");
            return; // Invalid data (legacy behavior)
        }

        // Read and skip RDATA length
        if (hardeningEnabled && !ValidateBounds(data, offset, 2, false))
        {
            throw new FormatException("SkipResourceRecord failed: insufficient bytes for RDATA length");
        }
        var rdataLength = ReadUInt16(data, ref offset, hardeningEnabled);

        // Validate RDATA length is reasonable (but be lenient for skipping)
        var maxRdataLength = securityConfig?.MaxRdataLength ?? 65535;
        if (hardeningEnabled)
        {
            // Only reject if RDATA length is clearly invalid (exceeds configured maximum)
            if (rdataLength > maxRdataLength)
            {
                throw new FormatException($"RDATA length ({rdataLength}) exceeds maximum ({maxRdataLength})");
            }
            // For SkipResourceRecord, be lenient - if RDATA exceeds buffer, just skip to end
            // This handles cases where messages might be partially corrupted but still parseable
        }

        // Skip RDATA (be lenient - if it exceeds buffer, just skip to end)
        if (offset + rdataLength <= data.Length)
        {
            offset += rdataLength;
        }
        else
        {
            // RDATA length exceeds buffer - just skip to end (don't throw for SkipResourceRecord)
            // This is safe because we're skipping records we don't need anyway
            offset = data.Length;
        }
    }

    /// <summary>
    /// Extracts serial number from SOA record RDATA.
    /// SOA RDATA format: MNAME (domain) + RNAME (domain) + SERIAL (4 bytes) + REFRESH + RETRY + EXPIRE + MINIMUM
    /// </summary>
    private static uint? ExtractSerialFromSoaRecord(SimpleDnsResourceRecord record)
    {
        return ExtractSerialFromSoaRecord(record, null);
    }

    private static uint? ExtractSerialFromSoaRecord(SimpleDnsResourceRecord record, SecurityConfig? securityConfig)
    {
        var hardeningEnabled = securityConfig?.SecurityHardeningEnabled ?? true;
        var maxCompressionDepth = securityConfig?.MaxCompressionPointerDepth ?? DefaultMaxCompressionPointerDepth;

        var rdata = record.Rdata;
        if (rdata != null && rdata.Length >= 4) // Need at least 4 bytes for serial
        {
            // Skip MNAME and RNAME (domain names)
            int offset = 0;
            var visitedOffsets = new HashSet<int>();
            int compressionDepth = 0;

            // Skip MNAME with loop detection
            while (offset < rdata.Length && rdata[offset] != 0)
            {
                if (hardeningEnabled && !ValidateBounds(rdata, offset, 1, false))
                {
                    return null; // Invalid data
                }

                if ((rdata[offset] & 0xC0) == 0xC0)
                {
                    // Compression pointer - in RDATA, these point to the original message buffer
                    // Since we're working with a copied RDATA array, we can't follow them correctly
                    // For SOA serial extraction, we can skip compression pointers and continue
                    // The compression is typically used for MNAME/RNAME which we're skipping anyway
                    if (hardeningEnabled)
                    {
                        compressionDepth++;
                        if (compressionDepth > maxCompressionDepth)
                        {
                            // Too many compression pointers - skip past this one and continue
                            if (offset + 2 <= rdata.Length)
                            {
                                offset += 2;
                                continue;
                            }
                            return null;
                        }
                        if (!ValidateBounds(rdata, offset, 2, false))
                        {
                            return null;
                        }
                        // Don't follow compression pointer - just skip past it
                        // The compressed name is elsewhere in the message, but we're only interested in the serial
                        offset += 2;
                        // Check if we've reached the end (compression pointer might be the terminator)
                        if (offset >= rdata.Length || rdata[offset] == 0)
                        {
                            break;
                        }
                        continue;
                    }
                    else
                    {
                        // Legacy behavior - skip compression pointer
                        offset += 2;
                        break;
                    }
                }
                var length = rdata[offset++];
                if (length == 0) break;
                if (hardeningEnabled && !ValidateBounds(rdata, offset, length, false))
                {
                    return null;
                }
                offset += length;
            }
            if (offset < rdata.Length && rdata[offset] == 0) offset++; // Skip terminator

            // Reset compression depth for RNAME
            compressionDepth = 0;
            visitedOffsets.Clear();

            // Skip RNAME with loop detection
            while (offset < rdata.Length && rdata[offset] != 0)
            {
                if (hardeningEnabled && !ValidateBounds(rdata, offset, 1, false))
                {
                    return null;
                }

                if ((rdata[offset] & 0xC0) == 0xC0)
                {
                    // Compression pointer - in RDATA, these point to the original message buffer
                    // Since we're working with a copied RDATA array, we can't follow them correctly
                    // For SOA serial extraction, we can skip compression pointers and continue
                    if (hardeningEnabled)
                    {
                        compressionDepth++;
                        if (compressionDepth > maxCompressionDepth)
                        {
                            // Too many compression pointers - skip past this one and continue
                            if (offset + 2 <= rdata.Length)
                            {
                                offset += 2;
                                continue;
                            }
                            return null;
                        }
                        if (!ValidateBounds(rdata, offset, 2, false))
                        {
                            return null;
                        }
                        // Don't follow compression pointer - just skip past it
                        offset += 2;
                        // Check if we've reached the end
                        if (offset >= rdata.Length || rdata[offset] == 0)
                        {
                            break;
                        }
                        continue;
                    }
                    else
                    {
                        // Legacy behavior - skip compression pointer
                        offset += 2;
                        break;
                    }
                }
                var length = rdata[offset++];
                if (length == 0) break;
                if (hardeningEnabled && !ValidateBounds(rdata, offset, length, false))
                {
                    return null;
                }
                offset += length;
            }
            if (offset < rdata.Length && rdata[offset] == 0) offset++; // Skip terminator

            // Read SERIAL (4 bytes)
            if (hardeningEnabled && !ValidateBounds(rdata, offset, 4, false))
            {
                return null;
            }

            if (offset + 4 <= rdata.Length)
            {
                var serial = (uint)((rdata[offset] << 24) | (rdata[offset + 1] << 16) | (rdata[offset + 2] << 8) | rdata[offset + 3]);
                return serial;
            }
        }

        return null;
    }


    private static uint ReadUInt32(byte[] data, ref int offset)
    {
        return ReadUInt32(data, ref offset, true);
    }

    private static uint ReadUInt32(byte[] data, ref int offset, bool validateBounds)
    {
        if (validateBounds && !ValidateBounds(data, offset, 4, true))
        {
            throw new FormatException("Cannot read UInt32: insufficient bytes");
        }

        if (offset + 4 > data.Length)
        {
            if (validateBounds)
                throw new FormatException("Cannot read UInt32: buffer overflow");
            return 0; // Legacy behavior
        }

        var value = (uint)((data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3]);
        offset += 4;
        return value;
    }
}

/// <summary>
/// Simple representation of a DNS resource record for parsing purposes.
/// </summary>
public class SimpleDnsResourceRecord
{
    public string DomainName { get; set; } = string.Empty;
    public DnsClient.Protocol.ResourceRecordType RecordType { get; set; }
    public DnsClient.QueryClass RecordClass { get; set; }
    public int TimeToLive { get; set; }
    public byte[]? Rdata { get; set; }

    public SimpleDnsResourceRecord(string domainName, DnsClient.Protocol.ResourceRecordType recordType, 
        DnsClient.QueryClass recordClass, int ttl, byte[]? rdata)
    {
        DomainName = domainName;
        RecordType = recordType;
        RecordClass = recordClass;
        TimeToLive = ttl;
        Rdata = rdata;
    }
}

