namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Self-describing header stored as the first entry (manifest.json) inside every backup
/// archive. Never contains key material itself - only metadata about what the archive
/// contains and a content hash to detect corruption/tampering on restore.
/// </summary>
public sealed class BackupManifest
{
    /// <summary>Bumped whenever the archive layout changes incompatibly. Restore rejects a manifest with an unsupported version.</summary>
    public required int SchemaVersion { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }
    public required string GatewayId { get; init; }
    public int? ActiveConfigurationVersion { get; init; }

    /// <summary>SHA-256 over the sorted "path|sha256(content)" lines of every included file (see Backup/BackupService.ComputeContentHash).</summary>
    public required string ContentSha256 { get; init; }

    public required IReadOnlyList<string> IncludedFiles { get; init; }
}

public sealed class BackupCreateResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public string? ArchivePath { get; init; }
    public BackupManifest? Manifest { get; init; }
    public required string Message { get; init; }
}

public sealed class BackupListEntry
{
    public required string ArchivePath { get; init; }
    public required bool Readable { get; init; }
    public BackupManifest? Manifest { get; init; }
    public string? Error { get; init; }
}

public sealed class BackupRestoreResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public BackupManifest? Manifest { get; init; }
    public required string Message { get; init; }
    public IReadOnlyList<string> RestoredFiles { get; init; } = Array.Empty<string>();
}
