using System.Collections.Concurrent;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using System.IO.Compression;
using DnsClient.Protocol;
using FilterDns.Export;
using FilterDns.Filter;
using FilterDns.Config;
using FilterDns.Dns;
using Microsoft.Extensions.Logging;

namespace FilterDns.Cache;

/// <summary>
/// JSON representation of a zone version for serialization.
/// </summary>
internal class ZoneVersionJson
{
    public uint Serial { get; set; }
    public List<FilteredRecordJson> Records { get; set; } = new();
    public DateTime Timestamp { get; set; }
    public string? Hash { get; set; } // SHA-256 hash for integrity checking
}

/// <summary>
/// JSON representation of a FilteredRecord for serialization.
/// </summary>
internal class FilteredRecordJson
{
    public string DomainName { get; set; } = string.Empty;
    public int RecordType { get; set; }
    public int RecordClass { get; set; }
    public int TimeToLive { get; set; }
    public SoaRecordDataJson? SoaData { get; set; }
    public string? NsName { get; set; }
    public string? RawRdataBase64 { get; set; } // For records we can't fully serialize
}

/// <summary>
/// JSON representation of SOA record data.
/// </summary>
internal class SoaRecordDataJson
{
    public string MName { get; set; } = string.Empty;
    public string RName { get; set; } = string.Empty;
    public uint Serial { get; set; }
    public uint Refresh { get; set; }
    public uint Retry { get; set; }
    public uint Expire { get; set; }
    public uint Minimum { get; set; }
}

/// <summary>
/// Handles persistent storage of zone history to disk.
/// Stores history in JSON format in {dataDir}/history/{zoneName}.json
/// </summary>
public class ZoneHistoryStorage
{
    private readonly string _dataDirectory;
    private readonly ILogger<ZoneHistoryStorage>? _logger;
    private readonly bool _exportBindZoneFiles;
    private readonly SecurityConfig? _securityConfig;

    public ZoneHistoryStorage(string dataDirectory, ILogger<ZoneHistoryStorage>? logger = null, bool exportBindZoneFiles = true, SecurityConfig? securityConfig = null)
    {
        _dataDirectory = dataDirectory ?? throw new ArgumentNullException(nameof(dataDirectory));
        _logger = logger;
        _exportBindZoneFiles = exportBindZoneFiles;
        _securityConfig = securityConfig;

        // Validate data directory path (security hardening)
        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        if (hardeningEnabled)
        {
            ValidateDataDirectoryPath(_dataDirectory);
        }

        // Ensure data directory exists
        if (!Directory.Exists(_dataDirectory))
        {
            Directory.CreateDirectory(_dataDirectory);
        }
        else
        {
            // Verify it's actually a directory, not a file
            if (hardeningEnabled && File.Exists(_dataDirectory))
            {
                throw new ArgumentException($"Data directory path '{_dataDirectory}' is a file, not a directory", nameof(dataDirectory));
            }
        }

        // Ensure history subdirectory exists
        var historyDir = Path.Combine(_dataDirectory, "history");
        if (!Directory.Exists(historyDir))
        {
            Directory.CreateDirectory(historyDir);
        }
    }

    /// <summary>
    /// Validates that the data directory path is safe and doesn't contain path traversal.
    /// </summary>
    private void ValidateDataDirectoryPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Data directory path cannot be null or empty", nameof(path));
        }

        // Resolve to absolute path
        var absolutePath = Path.GetFullPath(path);
        
        // Check for path traversal sequences
        if (absolutePath.Contains(".."))
        {
            throw new ArgumentException($"Data directory path contains path traversal sequence: {path}", nameof(path));
        }

        // Ensure path is absolute (not relative)
        if (!Path.IsPathRooted(absolutePath))
        {
            throw new ArgumentException($"Data directory path must be absolute: {path}", nameof(path));
        }
    }

    /// <summary>
    /// Validates and sanitizes a zone name for use in file paths.
    /// </summary>
    private string SanitizeZoneName(string zoneName)
    {
        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        var maxZoneNameLength = _securityConfig?.MaxZoneNameLength ?? 253;

        if (string.IsNullOrWhiteSpace(zoneName))
        {
            throw new ArgumentException("Zone name cannot be null or empty", nameof(zoneName));
        }

        if (hardeningEnabled)
        {
            // Check for path traversal sequences
            if (zoneName.Contains(".."))
            {
                throw new ArgumentException($"Zone name contains path traversal sequence: {zoneName}", nameof(zoneName));
            }

            // Check for path separators
            if (zoneName.Contains('/') || zoneName.Contains('\\'))
            {
                throw new ArgumentException($"Zone name contains path separator: {zoneName}", nameof(zoneName));
            }

            // Check for null bytes
            if (zoneName.Contains('\0'))
            {
                throw new ArgumentException("Zone name contains null byte", nameof(zoneName));
            }

            // Normalize Unicode (NFKC normalization)
            zoneName = zoneName.Normalize(NormalizationForm.FormKC);

            // Validate length
            if (zoneName.Length > maxZoneNameLength)
            {
                throw new ArgumentException($"Zone name length ({zoneName.Length}) exceeds maximum ({maxZoneNameLength})", nameof(zoneName));
            }

            // Whitelist approach: Only allow alphanumeric, underscore, hyphen, dot
            // This is more restrictive than DNS allows, but safer for file paths
            foreach (var c in zoneName)
            {
                if (!char.IsLetterOrDigit(c) && c != '_' && c != '-' && c != '.')
                {
                    throw new ArgumentException($"Zone name contains invalid character: '{c}' in '{zoneName}'", nameof(zoneName));
                }
            }
        }

        // Replace dots and spaces with underscores for filename safety
        var sanitized = zoneName
            .Replace(".", "_")
            .Replace(" ", "_")
            .Replace("/", "_")
            .Replace("\\", "_");

        return sanitized;
    }

    /// <summary>
    /// Validates that a file path stays within the data directory.
    /// </summary>
    private void ValidatePathWithinDirectory(string filePath, string baseDirectory)
    {
        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        if (!hardeningEnabled)
        {
            return; // Skip validation if hardening disabled
        }

        // Resolve to absolute paths
        var absoluteFilePath = Path.GetFullPath(filePath);
        var absoluteBaseDir = Path.GetFullPath(baseDirectory);

        // Ensure the file path is within the base directory
        if (!absoluteFilePath.StartsWith(absoluteBaseDir, StringComparison.Ordinal))
        {
            throw new System.Security.SecurityException($"Path '{filePath}' escapes data directory '{baseDirectory}'");
        }

        // Check for symlinks if protection is enabled
        if (_securityConfig?.EnableSymlinkProtection ?? true)
        {
            if (IsSymlink(filePath))
            {
                throw new System.Security.SecurityException($"Path '{filePath}' is a symlink, which is not allowed");
            }
        }
    }

    /// <summary>
    /// Checks if a path is a symlink.
    /// </summary>
    private bool IsSymlink(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                return false; // Path doesn't exist, can't be a symlink
            }

            var fileInfo = new FileInfo(path);
            if ((fileInfo.Attributes & FileAttributes.ReparsePoint) != 0)
            {
                return true;
            }
        }
        catch
        {
            // If we can't check, assume it's not a symlink (fail open for compatibility)
            return false;
        }

        return false;
    }

    /// <summary>
    /// Gets the file path for a zone's history.
    /// </summary>
    private string GetHistoryFilePath(string zoneName)
    {
        // Sanitize zone name with security validation
        var sanitizedZoneName = SanitizeZoneName(zoneName);

        var historyDir = Path.Combine(_dataDirectory, "history");
        var filePath = Path.Combine(historyDir, $"{sanitizedZoneName}.json");

        // Validate path stays within data directory
        ValidatePathWithinDirectory(filePath, _dataDirectory);

        return filePath;
    }

    /// <summary>
    /// Saves zone history to disk.
    /// Uses atomic writes (write to temp file, then rename).
    /// </summary>
    public async Task SaveAsync(ZoneHistory history)
    {
        if (history == null)
            throw new ArgumentNullException(nameof(history));

        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        var maxFileSize = _securityConfig?.MaxZoneHistoryFileSizeBytes ?? 104857600L;
        var maxVersions = _securityConfig?.MaxZoneVersionsPerZone ?? 100;
        var enableIntegrityChecks = _securityConfig?.EnableCacheIntegrityChecks ?? true;

        var filePath = GetHistoryFilePath(history.ZoneName);
        var tempFilePath = $"{filePath}.tmp";

        try
        {
            var allVersions = history.GetAllVersions().Values.ToList();
            if (hardeningEnabled && allVersions.Count > maxVersions)
            {
                _logger?.LogWarning(
                    "Zone history for {ZoneName} has {VersionCount} versions, exceeds maximum ({MaxVersions}). Saving only the newest versions.",
                    history.ZoneName, allVersions.Count, maxVersions);

                allVersions = allVersions
                    .OrderByDescending(v => v.Timestamp)
                    .ThenByDescending(v => v.Serial)
                    .Take(maxVersions)
                    .ToList();
            }

            // Convert to JSON format
            var versionsJson = new List<ZoneVersionJson>();
            foreach (var version in allVersions)
            {
                var recordsJson = version.Records.Select(ConvertToJson).ToList();
                var versionJson = new ZoneVersionJson
                {
                    Serial = version.Serial,
                    Timestamp = version.Timestamp,
                    Records = recordsJson
                };
                
                // Calculate and store hash if integrity checks enabled
                if (hardeningEnabled && enableIntegrityChecks)
                {
                    versionJson.Hash = CalculateZoneVersionHash(version.Serial, recordsJson, version.Timestamp);
                }
                
                versionsJson.Add(versionJson);
            }

            // Serialize to JSON
            var options = new JsonSerializerOptions
            {
                WriteIndented = false, // Compact format for smaller files
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var json = JsonSerializer.Serialize(versionsJson, options);
            var jsonBytes = System.Text.Encoding.UTF8.GetBytes(json);

            // Check file size limit before writing
            if (hardeningEnabled && jsonBytes.Length > maxFileSize)
            {
                throw new InvalidOperationException(
                    $"Zone history file size ({jsonBytes.Length} bytes) exceeds maximum ({maxFileSize} bytes) for zone {history.ZoneName}");
            }

            // Validate paths before file operations
            if (hardeningEnabled)
            {
                ValidatePathWithinDirectory(tempFilePath, _dataDirectory);
                ValidatePathWithinDirectory(filePath, _dataDirectory);
            }

            // Write to temp file
            await File.WriteAllBytesAsync(tempFilePath, jsonBytes);

            // Atomic replace without deleting the last known-good history first.
            if (File.Exists(filePath))
            {
                File.Replace(tempFilePath, filePath, null);
            }
            else
            {
                File.Move(tempFilePath, filePath);
            }

            // Also save each version as a BIND format zone file for human reference (if enabled)
            if (_exportBindZoneFiles)
            {
                await SaveBindZoneFilesAsync(history);
            }

            _logger?.LogDebug("Saved zone history for {ZoneName} ({VersionCount} versions) to {FilePath}",
                history.ZoneName, versionsJson.Count, filePath);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to save zone history for {ZoneName} to {FilePath}",
                history.ZoneName, filePath);

            // Clean up temp file if it exists
            try
            {
                if (File.Exists(tempFilePath))
                {
                    File.Delete(tempFilePath);
                }
            }
            catch
            {
                // Ignore cleanup errors
            }

            throw;
        }
    }

    /// <summary>
    /// Loads zone history from disk.
    /// Returns null if file doesn't exist or is invalid.
    /// </summary>
    public async Task<ZoneHistory?> LoadAsync(string zoneName)
    {
        if (string.IsNullOrEmpty(zoneName))
            throw new ArgumentException("Zone name cannot be null or empty", nameof(zoneName));

        var filePath = GetHistoryFilePath(zoneName);

        if (!File.Exists(filePath))
        {
            _logger?.LogDebug("No history file found for zone {ZoneName} at {FilePath}", zoneName, filePath);
            return null;
        }

        try
        {
            var jsonBytes = await File.ReadAllBytesAsync(filePath);
            var json = System.Text.Encoding.UTF8.GetString(jsonBytes);

            var options = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var versionsJson = JsonSerializer.Deserialize<List<ZoneVersionJson>>(json, options);

            if (versionsJson == null)
            {
                _logger?.LogWarning("Failed to deserialize zone history for {ZoneName} from {FilePath}",
                    zoneName, filePath);
                QuarantineInvalidHistoryFile(filePath, zoneName, "deserialized history was null");
                return null;
            }

            var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
            var enableIntegrityChecks = _securityConfig?.EnableCacheIntegrityChecks ?? true;

            var history = new ZoneHistory(zoneName);

            foreach (var versionJson in versionsJson)
            {
                // Validate integrity hash if enabled
                if (hardeningEnabled && enableIntegrityChecks && !string.IsNullOrEmpty(versionJson.Hash))
                {
                    var calculatedHash = CalculateZoneVersionHash(versionJson.Serial, versionJson.Records, versionJson.Timestamp);
                    if (calculatedHash != versionJson.Hash)
                    {
                        throw new InvalidDataException(
                            $"Zone history integrity check failed for {zoneName} version {versionJson.Serial}: hash mismatch. Expected {versionJson.Hash}, got {calculatedHash}");
                    }
                }
                
                var records = versionJson.Records.Select(ConvertFromJson).ToList();
                history.AddVersion(versionJson.Serial, records);
            }

            _logger?.LogDebug("Loaded zone history for {ZoneName} ({VersionCount} versions) from {FilePath}",
                zoneName, versionsJson.Count, filePath);

            return history;
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to load zone history for {ZoneName} from {FilePath}",
                zoneName, filePath);
            QuarantineInvalidHistoryFile(filePath, zoneName, ex.Message);
            return null;
        }
    }

    private void QuarantineInvalidHistoryFile(string filePath, string zoneName, string reason)
    {
        if (!File.Exists(filePath))
        {
            return;
        }

        try
        {
            var historyDir = Path.Combine(_dataDirectory, "history");
            var invalidDir = Path.Combine(historyDir, "invalid");
            Directory.CreateDirectory(invalidDir);
            ValidatePathWithinDirectory(invalidDir, _dataDirectory);

            var sanitizedZoneName = SanitizeZoneName(zoneName);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            var archivePath = Path.Combine(invalidDir, $"{sanitizedZoneName}_{timestamp}.zip");
            ValidatePathWithinDirectory(archivePath, _dataDirectory);

            using (var archive = ZipFile.Open(archivePath, ZipArchiveMode.Create))
            {
                archive.CreateEntryFromFile(filePath, Path.GetFileName(filePath), CompressionLevel.Optimal);
                var reasonEntry = archive.CreateEntry("reason.txt", CompressionLevel.Optimal);
                using var writer = new StreamWriter(reasonEntry.Open(), Encoding.UTF8);
                writer.WriteLine($"Zone: {zoneName}");
                writer.WriteLine($"OriginalPath: {filePath}");
                writer.WriteLine($"ArchivedAtUtc: {DateTime.UtcNow:O}");
                writer.WriteLine($"Reason: {reason}");
            }

            File.Delete(filePath);
            _logger?.LogWarning(
                "Archived invalid zone history for {ZoneName} to {ArchivePath} and removed active file {FilePath}",
                zoneName, archivePath, filePath);
        }
        catch (Exception archiveEx)
        {
            _logger?.LogError(
                archiveEx,
                "Failed to archive invalid zone history for {ZoneName} at {FilePath}; leaving active file in place",
                zoneName,
                filePath);
        }
    }

    /// <summary>
    /// Deletes the history file for a zone.
    /// </summary>
    public void Delete(string zoneName)
    {
        var filePath = GetHistoryFilePath(zoneName);

        try
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
                _logger?.LogDebug("Deleted zone history file for {ZoneName} at {FilePath}", zoneName, filePath);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to delete zone history file for {ZoneName} at {FilePath}",
                zoneName, filePath);
            throw;
        }
    }

    /// <summary>
    /// Converts a FilteredRecord to JSON format.
    /// </summary>
    private FilteredRecordJson ConvertToJson(FilteredRecord record)
    {
        var json = new FilteredRecordJson
        {
            DomainName = record.DomainName,
            RecordType = (int)record.RecordType,
            RecordClass = (int)record.RecordClass,
            TimeToLive = record.TimeToLive,
            NsName = record.NsName
        };

        if (record.SoaData != null)
        {
            json.SoaData = new SoaRecordDataJson
            {
                MName = record.SoaData.MName,
                RName = record.SoaData.RName,
                Serial = record.SoaData.Serial,
                Refresh = record.SoaData.Refresh,
                Retry = record.SoaData.Retry,
                Expire = record.SoaData.Expire,
                Minimum = record.SoaData.Minimum
            };
        }

        var rawRdata = RDataSerializer.Serialize(record);
        if (rawRdata.Length > 0)
        {
            json.RawRdataBase64 = Convert.ToBase64String(rawRdata);
        }
        else if (RequiresRawRdata(json))
        {
            throw new InvalidOperationException(
                $"Record {record.DomainName} type {record.RecordType} cannot be persisted without raw RDATA");
        }

        return json;
    }

    /// <summary>
    /// Converts a FilteredRecordJson back to FilteredRecord.
    /// Note: OriginalRecord will be null as we can't fully restore it from JSON.
    /// This is acceptable for IXFR purposes as we mainly work with FilteredRecord data.
    /// </summary>
    private FilteredRecord ConvertFromJson(FilteredRecordJson json)
    {
        if (string.IsNullOrEmpty(json.RawRdataBase64) && RequiresRawRdata(json))
        {
            throw new InvalidDataException(
                $"Persisted record {json.DomainName} type {json.RecordType} is missing raw RDATA and cannot be safely used for IXFR");
        }

        var record = new FilteredRecord
        {
            DomainName = json.DomainName,
            RecordType = (ResourceRecordType)json.RecordType,
            RecordClass = (DnsClient.QueryClass)json.RecordClass,
            TimeToLive = json.TimeToLive,
            NsName = json.NsName,
            RawRData = string.IsNullOrEmpty(json.RawRdataBase64) ? null : Convert.FromBase64String(json.RawRdataBase64),
            OriginalRecord = null! // Cannot restore from JSON
        };

        if (json.SoaData != null)
        {
            record.SoaData = new SoaRecordData
            {
                MName = json.SoaData.MName,
                RName = json.SoaData.RName,
                Serial = json.SoaData.Serial,
                Refresh = json.SoaData.Refresh,
                Retry = json.SoaData.Retry,
                Expire = json.SoaData.Expire,
                Minimum = json.SoaData.Minimum
            };
        }

        return record;
    }

    private static bool RequiresRawRdata(FilteredRecordJson json)
    {
        var recordType = (ResourceRecordType)json.RecordType;
        return recordType switch
        {
            ResourceRecordType.SOA => json.SoaData == null,
            ResourceRecordType.NS => string.IsNullOrEmpty(json.NsName),
            _ => true
        };
    }

    /// <summary>
    /// Gets the directory path for BIND zone files.
    /// </summary>
    private string GetZoneFilesDirectory()
    {
        return Path.Combine(_dataDirectory, "history", "zones");
    }

    /// <summary>
    /// Gets the file path for a zone version in BIND format.
    /// Public method for use by DnsProxyServer.
    /// </summary>
    public string GetZoneFilePath(string zoneName, uint serial)
    {
        // Validate serial number is reasonable
        var hardeningEnabled = _securityConfig?.SecurityHardeningEnabled ?? true;
        if (hardeningEnabled && serial == 0)
        {
            throw new ArgumentException("Serial number cannot be zero", nameof(serial));
        }

        // Sanitize zone name with security validation
        var sanitizedZoneName = SanitizeZoneName(zoneName);

        var zoneFilesDir = GetZoneFilesDirectory();
        var filePath = Path.Combine(zoneFilesDir, $"{sanitizedZoneName}_{serial}.zone");

        // Validate path stays within data directory
        ValidatePathWithinDirectory(filePath, _dataDirectory);

        return filePath;
    }


    /// <summary>
    /// Saves each version in the history as a BIND format zone file.
    /// Only writes files that don't already exist to preserve their original timestamps.
    /// </summary>
    private async Task SaveBindZoneFilesAsync(ZoneHistory history)
    {
        try
        {
            var zoneFilesDir = GetZoneFilesDirectory();
            if (!Directory.Exists(zoneFilesDir))
            {
                Directory.CreateDirectory(zoneFilesDir);
            }

            var filesCreated = 0;
            var filesSkipped = 0;

            foreach (var version in history.GetAllVersions().Values)
            {
                var zoneFilePath = GetZoneFilePath(history.ZoneName, version.Serial);
                
                // Only write if file doesn't exist - this preserves the original timestamp
                // Since serial numbers are unique per zone version, existing files never need updating
                if (!File.Exists(zoneFilePath))
                {
                    await ZoneExporter.ExportToFileAsync(version.Records, history.ZoneName, zoneFilePath);
                    filesCreated++;
                }
                else
                {
                    filesSkipped++;
                }
            }

            _logger?.LogDebug("Saved BIND zone files for {ZoneName} ({CreatedCount} created, {SkippedCount} skipped, {TotalCount} total versions)",
                history.ZoneName, filesCreated, filesSkipped, history.Count);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to save BIND zone files for {ZoneName}", history.ZoneName);
            // Don't throw - this is optional, JSON is the primary storage
        }
    }

    /// <summary>
    /// Cleans up old zone files based on retention policy.
    /// </summary>
    public void CleanupOldZoneFiles(int retentionDays)
    {
        try
        {
            var zoneFilesDir = GetZoneFilesDirectory();
            if (!Directory.Exists(zoneFilesDir))
            {
                return; // Nothing to clean
            }

            var cutoffDate = DateTime.UtcNow.AddDays(-retentionDays);
            var filesDeleted = 0;
            var totalSizeDeleted = 0L;

            var zoneFiles = Directory.GetFiles(zoneFilesDir, "*.zone");
            foreach (var filePath in zoneFiles)
            {
                try
                {
                    var fileInfo = new FileInfo(filePath);
                    if (fileInfo.LastWriteTimeUtc < cutoffDate)
                    {
                        var fileSize = fileInfo.Length;
                        File.Delete(filePath);
                        filesDeleted++;
                        totalSizeDeleted += fileSize;
                    }
                }
                catch (Exception ex)
                {
                    _logger?.LogWarning(ex, "Failed to delete old zone file {FilePath}", filePath);
                }
            }

            if (filesDeleted > 0)
            {
                _logger?.LogInformation("Cleaned up {FileCount} old zone files ({Size} bytes) older than {RetentionDays} days",
                    filesDeleted, totalSizeDeleted, retentionDays);
            }
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Failed to cleanup old zone files");
        }
    }

    /// <summary>
    /// Calculates SHA-256 hash of a zone version for integrity checking.
    /// </summary>
    private string CalculateZoneVersionHash(uint serial, List<FilteredRecordJson> records, DateTime timestamp)
    {
        // Create a deterministic representation of the zone version
        // Include serial, timestamp, and record count for basic integrity
        // For full integrity, we'd hash all record data, but that's expensive
        // This provides reasonable protection against corruption
        
        var hashInput = $"{serial}|{timestamp:O}|{records.Count}";
        
        // Include a hash of record data for stronger integrity
        var recordsHash = string.Join("|", records.Select(r => 
            $"{r.DomainName}:{r.RecordType}:{r.RecordClass}:{r.TimeToLive}:{r.NsName}:{r.RawRdataBase64}:{SerializeSoaForHash(r.SoaData)}"));
        
        hashInput += $"|{recordsHash}";
        
        var inputBytes = System.Text.Encoding.UTF8.GetBytes(hashInput);
        var hashBytes = SHA256.HashData(inputBytes);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }

    private static string SerializeSoaForHash(SoaRecordDataJson? soaData)
    {
        if (soaData == null)
        {
            return string.Empty;
        }

        return $"{soaData.MName}:{soaData.RName}:{soaData.Serial}:{soaData.Refresh}:{soaData.Retry}:{soaData.Expire}:{soaData.Minimum}";
    }
}
