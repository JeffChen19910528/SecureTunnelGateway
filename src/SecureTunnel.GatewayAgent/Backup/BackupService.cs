using System.Formats.Tar;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Backup;

public sealed class BackupService : IBackupService
{
    private const int CurrentSchemaVersion = 1;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly ILogger<BackupService> _logger;

    public BackupService(ILogger<BackupService> logger)
    {
        _logger = logger;
    }

    public async Task<BackupCreateResult> CreateAsync(GatewayConfiguration config, string configPath, string? outputPath, bool dryRun, CancellationToken cancellationToken = default)
    {
        var files = CollectExistingFiles(config, configPath);
        if (files.Count == 0)
        {
            return new BackupCreateResult { Success = false, DryRun = dryRun, Message = "Nothing to back up: none of the expected files (gateway.yaml, Registries, WireGuard keys) exist yet." };
        }

        var contents = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (name, path) in files)
        {
            contents[name] = await File.ReadAllBytesAsync(path, cancellationToken);
        }

        var manifest = new BackupManifest
        {
            SchemaVersion = CurrentSchemaVersion,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            GatewayId = config.GatewayId,
            ContentSha256 = ComputeContentHash(contents),
            IncludedFiles = contents.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList()
        };

        if (dryRun)
        {
            return new BackupCreateResult
            {
                Success = true,
                DryRun = true,
                Manifest = manifest,
                Message = $"[DRY-RUN] Would create a backup containing {manifest.IncludedFiles.Count} file(s): {string.Join(", ", manifest.IncludedFiles)}. Nothing was written."
            };
        }

        var finalPath = outputPath ?? Path.Combine(config.BackupDirectory, $"securetunnel-backup-{manifest.CreatedAtUtc:yyyyMMddTHHmmssZ}.tar.gz");

        if (File.Exists(finalPath))
        {
            return new BackupCreateResult { Success = false, DryRun = false, Message = $"'{finalPath}' already exists. Refusing to overwrite a backup archive." };
        }

        var directory = Path.GetDirectoryName(finalPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = finalPath + $".tmp-{Guid.NewGuid():N}";
        try
        {
            await WriteArchiveAsync(tempPath, manifest, contents, cancellationToken);
            File.Move(tempPath, finalPath);

            if (!OperatingSystem.IsWindows())
            {
                // The archive can contain the server private key - treat it with the same
                // owner-only permissions as the key file itself (see docs/security-model.md).
                File.SetUnixFileMode(finalPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception ex)
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { /* best-effort */ }
            }
            _logger.LogError(ex, "Failed to write backup archive to {Path}", finalPath);
            return new BackupCreateResult { Success = false, DryRun = false, Message = $"Failed to write backup archive: {ex.Message}" };
        }

        _logger.LogInformation("Created backup {Path} with {Count} file(s)", finalPath, manifest.IncludedFiles.Count);

        return new BackupCreateResult
        {
            Success = true,
            DryRun = false,
            ArchivePath = finalPath,
            Manifest = manifest,
            Message = $"Backup created at '{finalPath}' ({manifest.IncludedFiles.Count} file(s)). Store this archive as securely as a private key - it may contain the server private key."
        };
    }

    public async Task<IReadOnlyList<BackupListEntry>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        var results = new List<BackupListEntry>();
        if (!Directory.Exists(config.BackupDirectory))
        {
            return results;
        }

        foreach (var path in Directory.EnumerateFiles(config.BackupDirectory, "*.tar.gz").OrderBy(p => p, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var manifest = await ReadManifestAsync(path, cancellationToken);
                results.Add(new BackupListEntry { ArchivePath = path, Readable = true, Manifest = manifest });
            }
            catch (Exception ex)
            {
                results.Add(new BackupListEntry { ArchivePath = path, Readable = false, Error = ex.Message });
            }
        }

        return results;
    }

    public async Task<BackupRestoreResult> RestoreAsync(GatewayConfiguration config, string configPath, string archivePath, bool dryRun, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(archivePath))
        {
            return new BackupRestoreResult { Success = false, DryRun = dryRun, Message = $"Backup archive '{archivePath}' not found." };
        }

        Dictionary<string, byte[]> extracted;
        BackupManifest manifest;
        try
        {
            (manifest, extracted) = await ReadArchiveAsync(archivePath, cancellationToken);
        }
        catch (Exception ex)
        {
            return new BackupRestoreResult { Success = false, DryRun = dryRun, Message = $"Could not read backup archive: {ex.Message}" };
        }

        if (manifest.SchemaVersion != CurrentSchemaVersion)
        {
            return new BackupRestoreResult
            {
                Success = false,
                DryRun = dryRun,
                Manifest = manifest,
                Message = $"Backup schema version {manifest.SchemaVersion} is not supported by this Gateway Agent (expects {CurrentSchemaVersion}). Refusing to restore an incompatible backup."
            };
        }

        var recomputedHash = ComputeContentHash(extracted);
        if (!string.Equals(recomputedHash, manifest.ContentSha256, StringComparison.OrdinalIgnoreCase))
        {
            return new BackupRestoreResult
            {
                Success = false,
                DryRun = dryRun,
                Manifest = manifest,
                Message = "Backup integrity check failed: recomputed content hash does not match the manifest. The archive is corrupted or was tampered with. Refusing to restore."
            };
        }

        var warning = string.Equals(manifest.GatewayId, config.GatewayId, StringComparison.Ordinal)
            ? string.Empty
            : $" WARNING: backup was taken from gateway '{manifest.GatewayId}', current gateway is '{config.GatewayId}'.";

        if (dryRun)
        {
            return new BackupRestoreResult
            {
                Success = true,
                DryRun = true,
                Manifest = manifest,
                RestoredFiles = manifest.IncludedFiles,
                Message = $"[DRY-RUN] Integrity check passed. Would restore {manifest.IncludedFiles.Count} file(s): {string.Join(", ", manifest.IncludedFiles)}.{warning} " +
                          "Nothing was written; the running WireGuard/nftables state would not be touched either way - an explicit `config apply` is always required afterward to activate restored data."
            };
        }

        // Archive entry names are looked up as KEYS into this fixed, trusted map - never
        // used as a literal filesystem path - so an archive containing an entry named e.g.
        // "../../etc/passwd" cannot write outside the expected target paths (path-traversal
        // safe by construction; see RestoreAsync_ArchiveWithUnrecognizedEntryName_IsSkipped_
        // NeverWrittenAsALiteralPath in BackupServiceTests for the regression proof).
        var targets = CollectTargetPaths(config, configPath);
        var restored = new List<string>();
        var backupSuffix = $".pre-restore-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssZ}";

        // Fail closed, honestly, on a partial restore: if any individual file write throws
        // partway through, stop immediately rather than continuing (which could apply some
        // files but not others) or letting the exception propagate unhandled (which would
        // hide exactly which files DID already change). Files restored before the failure
        // are reported by name so the operator knows precisely what changed.
        try
        {
            foreach (var (name, content) in extracted)
            {
                if (!targets.TryGetValue(name, out var targetPath))
                {
                    _logger.LogWarning("Backup contains unrecognized entry '{Name}'; skipping it.", name);
                    continue;
                }

                var directory = Path.GetDirectoryName(targetPath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                // Preserve the previous recoverable state before overwriting anything.
                if (File.Exists(targetPath))
                {
                    File.Copy(targetPath, targetPath + backupSuffix, overwrite: true);
                }

                var tempPath = targetPath + $".tmp-{Guid.NewGuid():N}";
                await File.WriteAllBytesAsync(tempPath, content, cancellationToken);
                File.Move(tempPath, targetPath, overwrite: true);

                if (!OperatingSystem.IsWindows() && (name.StartsWith("keys/", StringComparison.Ordinal) || name.EndsWith(".json", StringComparison.Ordinal)))
                {
                    File.SetUnixFileMode(targetPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                restored.Add(name);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Restore from {Path} failed partway through after restoring {Count} file(s): {Files}", archivePath, restored.Count, string.Join(", ", restored));
            return new BackupRestoreResult
            {
                Success = false,
                DryRun = false,
                Manifest = manifest,
                RestoredFiles = restored,
                Message = $"Restore FAILED partway through: {ex.Message} " +
                          $"{(restored.Count > 0 ? $"{restored.Count} file(s) were already restored before the failure: {string.Join(", ", restored)} (previous versions preserved with a '{backupSuffix}' suffix)." : "No files were restored.")} " +
                          "This restore is INCOMPLETE - do NOT run `config apply`. Investigate the error and either retry the restore or manually reconcile the affected files."
            };
        }

        _logger.LogInformation("Restored {Count} file(s) from backup {Path}", restored.Count, archivePath);

        return new BackupRestoreResult
        {
            Success = true,
            DryRun = false,
            Manifest = manifest,
            RestoredFiles = restored,
            Message = $"Restored {restored.Count} file(s).{warning} Previous files (if any) were preserved with a '{backupSuffix}' suffix. " +
                      "This data is NOT yet active - run `securetunnel-gateway config apply --yes` to validate and activate it."
        };
    }

    private static Dictionary<string, string> CollectExistingFiles(GatewayConfiguration config, string configPath)
    {
        var candidates = CollectTargetPaths(config, configPath);
        return candidates.Where(kv => File.Exists(kv.Value)).ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.Ordinal);
    }

    /// <summary>Archive-relative name -> current on-disk path, based on the CURRENT gateway.yaml (used both to decide what to include and where to restore).</summary>
    private static Dictionary<string, string> CollectTargetPaths(GatewayConfiguration config, string configPath) => new(StringComparer.Ordinal)
    {
        ["gateway.yaml"] = configPath,
        ["peers.json"] = config.PeerStorePath,
        ["resources.json"] = config.ResourceStorePath,
        ["policies.json"] = config.PolicyStorePath,
        ["config-history.json"] = config.ConfigurationHistoryPath,
        ["keys/server.key"] = config.WireGuard.PrivateKeyPath,
        ["keys/server.pub"] = config.WireGuard.PublicKeyPath
    };

    private static string ComputeContentHash(IReadOnlyDictionary<string, byte[]> files)
    {
        var sb = new StringBuilder();
        foreach (var name in files.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            var fileHash = Convert.ToHexString(SHA256.HashData(files[name])).ToLowerInvariant();
            sb.Append(name).Append('|').Append(fileHash).Append('\n');
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()))).ToLowerInvariant();
    }

    private static async Task WriteArchiveAsync(string path, BackupManifest manifest, IReadOnlyDictionary<string, byte[]> files, CancellationToken cancellationToken)
    {
        await using var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
        await using var gzip = new GZipStream(fileStream, CompressionLevel.Optimal);
        await using var tarWriter = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false);

        var manifestJson = JsonSerializer.SerializeToUtf8Bytes(manifest, JsonOptions);
        await WriteEntryAsync(tarWriter, "manifest.json", manifestJson, cancellationToken);

        foreach (var (name, content) in files)
        {
            await WriteEntryAsync(tarWriter, name, content, cancellationToken);
        }
    }

    private static async Task WriteEntryAsync(TarWriter writer, string name, byte[] content, CancellationToken cancellationToken)
    {
        var entry = new PaxTarEntry(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(content)
        };
        await writer.WriteEntryAsync(entry, cancellationToken);
    }

    private static async Task<BackupManifest> ReadManifestAsync(string archivePath, CancellationToken cancellationToken)
    {
        var (manifest, _) = await ReadArchiveAsync(archivePath, cancellationToken, manifestOnly: true);
        return manifest;
    }

    private static async Task<(BackupManifest Manifest, Dictionary<string, byte[]> Files)> ReadArchiveAsync(string archivePath, CancellationToken cancellationToken, bool manifestOnly = false)
    {
        await using var fileStream = new FileStream(archivePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        await using var gzip = new GZipStream(fileStream, CompressionMode.Decompress);
        await using var tarReader = new TarReader(gzip, leaveOpen: false);

        BackupManifest? manifest = null;
        var files = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        while (await tarReader.GetNextEntryAsync(cancellationToken: cancellationToken) is { } entry)
        {
            if (entry.EntryType != TarEntryType.RegularFile || entry.DataStream is null)
            {
                continue;
            }

            using var buffer = new MemoryStream();
            await entry.DataStream.CopyToAsync(buffer, cancellationToken);
            var bytes = buffer.ToArray();

            if (entry.Name == "manifest.json")
            {
                manifest = JsonSerializer.Deserialize<BackupManifest>(bytes, JsonOptions)
                           ?? throw new InvalidDataException("manifest.json deserialized to null.");
                if (manifestOnly)
                {
                    break;
                }
            }
            else
            {
                files[entry.Name] = bytes;
            }
        }

        if (manifest is null)
        {
            throw new InvalidDataException("Archive does not contain a manifest.json entry.");
        }

        return (manifest, files);
    }
}
