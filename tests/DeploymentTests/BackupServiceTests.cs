using System.Formats.Tar;
using System.IO.Compression;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Backup;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.DeploymentTests;

public sealed class BackupServiceTests : IDisposable
{
    private readonly List<string> _tempPaths = new();
    private readonly BackupService _service = new(NullLogger<BackupService>.Instance);

    [Fact]
    public async Task CreateAsync_NoFilesExist_ReturnsFailureNotEmptyArchive()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = NonExistentPath();
        SetIsolatedPaths(config);

        var result = await _service.CreateAsync(config, configPath, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("Nothing to back up", result.Message);
    }

    [Fact]
    public async Task CreateAsync_DryRun_DoesNotWriteArchive()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        WriteFile(config.PeerStorePath, "[]");

        var result = await _service.CreateAsync(config, configPath, null, dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.False(Directory.Exists(config.BackupDirectory) && Directory.GetFiles(config.BackupDirectory).Length > 0);
    }

    [Fact]
    public async Task CreateAsync_ThenListAsync_ShowsTheBackup()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        WriteFile(config.PeerStorePath, "[]");

        var create = await _service.CreateAsync(config, configPath, null, dryRun: false);
        Assert.True(create.Success);

        var list = await _service.ListAsync(config);

        var entry = Assert.Single(list);
        Assert.True(entry.Readable);
        Assert.Equal(config.GatewayId, entry.Manifest!.GatewayId);
    }

    [Fact]
    public async Task CreateAsync_IncludesServerPrivateKey_ButManifestNeverContainsItsContent()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        WriteFile(config.PeerStorePath, "[]");
        WriteFile(config.WireGuard.PrivateKeyPath, "SUPER_SECRET_PRIVATE_KEY_VALUE=");

        var result = await _service.CreateAsync(config, configPath, null, dryRun: false);

        Assert.True(result.Success);
        Assert.Contains("keys/server.key", result.Manifest!.IncludedFiles);
        // The manifest/result surfaced to the caller must never contain the actual key bytes -
        // only file names and hashes.
        Assert.DoesNotContain("SUPER_SECRET_PRIVATE_KEY_VALUE", result.Message);
        foreach (var file in result.Manifest.IncludedFiles)
        {
            Assert.DoesNotContain("SUPER_SECRET", file);
        }
    }

    [Fact]
    public async Task RestoreAsync_DryRun_PassesIntegrityCheckAndTouchesNothing()
    {
        var (config, configPath, archivePath) = await CreateBackupWithContentAsync();

        var result = await _service.RestoreAsync(config, configPath, archivePath, dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Contains("peers.json", result.RestoredFiles);
    }

    [Fact]
    public async Task RestoreAsync_Real_WritesFilesAndPreservesPrevious()
    {
        var (config, configPath, archivePath) = await CreateBackupWithContentAsync();

        // Change the live peers.json after the backup so we can prove restore overwrites it
        // and preserves what was there.
        await File.WriteAllTextAsync(config.PeerStorePath, "[\"CHANGED-AFTER-BACKUP\"]");

        var result = await _service.RestoreAsync(config, configPath, archivePath, dryRun: false);

        Assert.True(result.Success);
        Assert.Contains("Restored", result.Message);
        Assert.Contains("config apply", result.Message);

        var restoredContent = await File.ReadAllTextAsync(config.PeerStorePath);
        Assert.DoesNotContain("CHANGED-AFTER-BACKUP", restoredContent);

        var preserved = Directory.GetFiles(Path.GetDirectoryName(config.PeerStorePath)!, "*.pre-restore-*");
        Assert.Contains(preserved, p => File.ReadAllText(p).Contains("CHANGED-AFTER-BACKUP"));
    }

    [Fact]
    public async Task RestoreAsync_CorruptedArchive_RejectedWithoutWriting()
    {
        var (config, configPath, archivePath) = await CreateBackupWithContentAsync();

        // Flip a byte in the middle of the compressed stream - this corrupts the tar
        // content (and, in this small test archive, virtually always breaks gzip
        // decompression outright, which the service must also treat as "could not
        // restore" rather than crashing or silently proceeding).
        var bytes = await File.ReadAllBytesAsync(archivePath);
        bytes[bytes.Length / 2] ^= 0xFF;
        await File.WriteAllBytesAsync(archivePath, bytes);

        var beforeContent = await File.ReadAllTextAsync(config.PeerStorePath);

        var result = await _service.RestoreAsync(config, configPath, archivePath, dryRun: false);

        Assert.False(result.Success);
        var afterContent = await File.ReadAllTextAsync(config.PeerStorePath);
        Assert.Equal(beforeContent, afterContent); // untouched
    }

    [Fact]
    public async Task RestoreAsync_UnsupportedSchemaVersion_Rejected()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        var beforeContent = "[\"UNCHANGED\"]";
        WriteFile(config.PeerStorePath, beforeContent);

        var archivePath = await WriteHandCraftedArchiveAsync(schemaVersion: 999);

        var result = await _service.RestoreAsync(config, configPath, archivePath, dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("not supported", result.Message);
        Assert.Equal(beforeContent, await File.ReadAllTextAsync(config.PeerStorePath));
    }

    /// <summary>Builds a minimal, otherwise-valid archive but with an unsupported manifest SchemaVersion, to test restore's version gate independent of the integrity-hash gate.</summary>
    private async Task<string> WriteHandCraftedArchiveAsync(int schemaVersion)
    {
        var path = TempPath();
        var manifest = new BackupManifest
        {
            SchemaVersion = schemaVersion,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            GatewayId = "gw-test",
            ContentSha256 = "0000000000000000000000000000000000000000000000000000000000000",
            IncludedFiles = new List<string> { "peers.json" }
        };

        await using (var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        await using (var gzip = new GZipStream(fileStream, CompressionLevel.Optimal))
        await using (var tarWriter = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false))
        {
            var manifestEntry = new PaxTarEntry(TarEntryType.RegularFile, "manifest.json")
            {
                DataStream = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true }))
            };
            await tarWriter.WriteEntryAsync(manifestEntry);

            var peersEntry = new PaxTarEntry(TarEntryType.RegularFile, "peers.json")
            {
                DataStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes("[]"))
            };
            await tarWriter.WriteEntryAsync(peersEntry);
        }

        return path;
    }

    [Fact]
    public async Task RestoreAsync_ArchiveWithUnrecognizedEntryName_IsSkipped_NeverWrittenAsALiteralPath()
    {
        // Phase 7 hardening regression: an archive entry name is only ever used as a lookup
        // KEY into BackupService's fixed target-path map - never concatenated into a literal
        // filesystem path - so a traversal-style entry name is inert by construction.
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        var beforeContent = "[\"UNCHANGED\"]";
        WriteFile(config.PeerStorePath, beforeContent);

        var canaryPath = Path.Combine(Path.GetTempPath(), $"securetunnel-backuptest-canary-{Guid.NewGuid():N}");
        _tempPaths.Add(canaryPath);
        var archivePath = await WriteArchiveWithExtraEntryAsync("../../evil.txt", "should never be written anywhere");

        var result = await _service.RestoreAsync(config, configPath, archivePath, dryRun: false);

        Assert.True(result.Success);
        Assert.DoesNotContain("../../evil.txt", result.RestoredFiles);
        Assert.False(File.Exists(canaryPath));
        Assert.False(File.Exists(Path.Combine(Path.GetTempPath(), "evil.txt")));
    }

    [Fact]
    public async Task RestoreAsync_FailurePartwayThrough_ReportsWhichFilesWereAlreadyRestored_NotSilentlySuccess()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        WriteFile(config.PeerStorePath, "[\"ORIGINAL-PEERS\"]");

        var workingResourcePath = TempPath();
        File.WriteAllText(workingResourcePath, "[]");
        config.ResourceStorePath = workingResourcePath;

        var create = await _service.CreateAsync(config, configPath, null, dryRun: false);
        Assert.True(create.Success);
        Assert.Contains("peers.json", create.Manifest!.IncludedFiles);
        Assert.Contains("resources.json", create.Manifest.IncludedFiles);

        // Now repoint ResourceStorePath so its parent segment is an existing FILE (not a
        // directory) - Directory.CreateDirectory(...) for it will throw when the restore
        // loop reaches resources.json, deterministically exercising the mid-restore
        // failure path AFTER peers.json (which sorts first) has already been restored.
        var blockerFile = TempPath();
        File.WriteAllText(blockerFile, "not a directory");
        config.ResourceStorePath = Path.Combine(blockerFile, "resources.json");

        var result = await _service.RestoreAsync(config, configPath, create.ArchivePath!, dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("INCOMPLETE", result.Message);
        Assert.Contains("peers.json", result.RestoredFiles);
        Assert.DoesNotContain("resources.json", result.RestoredFiles);
    }

    /// <summary>Builds a valid, integrity-passing archive containing "peers.json" plus one extra, unrecognized entry name (to test the path-traversal-safety regression).</summary>
    private async Task<string> WriteArchiveWithExtraEntryAsync(string extraEntryName, string extraEntryContent)
    {
        var path = TempPath();
        var peersContent = System.Text.Encoding.UTF8.GetBytes("[\"UNCHANGED\"]");
        var extraContent = System.Text.Encoding.UTF8.GetBytes(extraEntryContent);

        string Hash(byte[] bytes) => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

        // Mirrors BackupService.ComputeContentHash exactly: sorted "{name}|{sha256(content)}\n" lines, then sha256 of that.
        var names = new[] { extraEntryName, "peers.json" }.OrderBy(n => n, StringComparer.Ordinal);
        var sb = new System.Text.StringBuilder();
        foreach (var name in names)
        {
            var content = name == "peers.json" ? peersContent : extraContent;
            sb.Append(name).Append('|').Append(Hash(content)).Append('\n');
        }
        var contentHash = Hash(System.Text.Encoding.UTF8.GetBytes(sb.ToString()));

        var manifest = new BackupManifest
        {
            SchemaVersion = 1,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            GatewayId = "gw-test",
            ContentSha256 = contentHash,
            IncludedFiles = new List<string> { "peers.json", extraEntryName }
        };

        await using (var fileStream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
        await using (var gzip = new GZipStream(fileStream, CompressionLevel.Optimal))
        await using (var tarWriter = new TarWriter(gzip, TarEntryFormat.Pax, leaveOpen: false))
        {
            var manifestEntry = new PaxTarEntry(TarEntryType.RegularFile, "manifest.json")
            {
                DataStream = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(manifest, new JsonSerializerOptions { WriteIndented = true }))
            };
            await tarWriter.WriteEntryAsync(manifestEntry);

            var peersEntry = new PaxTarEntry(TarEntryType.RegularFile, "peers.json") { DataStream = new MemoryStream(peersContent) };
            await tarWriter.WriteEntryAsync(peersEntry);

            var extraEntry = new PaxTarEntry(TarEntryType.RegularFile, extraEntryName) { DataStream = new MemoryStream(extraContent) };
            await tarWriter.WriteEntryAsync(extraEntry);
        }

        _tempPaths.Add(path);
        return path;
    }

    [Fact]
    public async Task RestoreAsync_MissingArchive_ReturnsClearError()
    {
        var config = TestConfigurationFactory.CreateValid();
        SetIsolatedPaths(config);

        var result = await _service.RestoreAsync(config, "gateway.yaml", NonExistentPath(), dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("not found", result.Message);
    }

    private async Task<(Models.GatewayConfiguration Config, string ConfigPath, string ArchivePath)> CreateBackupWithContentAsync()
    {
        var config = TestConfigurationFactory.CreateValid();
        var configPath = WriteFile("gateway.yaml", "gatewayId: test");
        SetIsolatedPaths(config);
        WriteFile(config.PeerStorePath, "[\"ORIGINAL\"]");

        var create = await _service.CreateAsync(config, configPath, null, dryRun: false);
        Assert.True(create.Success);
        return (config, configPath, create.ArchivePath!);
    }

    private void SetIsolatedPaths(Models.GatewayConfiguration config)
    {
        config.PeerStorePath = TempPath();
        config.ResourceStorePath = NonExistentPath();
        config.PolicyStorePath = NonExistentPath();
        config.ConfigurationHistoryPath = NonExistentPath();
        config.WireGuard.PrivateKeyPath = NonExistentPath();
        config.WireGuard.PublicKeyPath = NonExistentPath();
        config.BackupDirectory = Path.Combine(Path.GetTempPath(), $"securetunnel-backupdir-{Guid.NewGuid():N}");
        _tempPaths.Add(config.BackupDirectory);
    }

    private string WriteFile(string path, string content)
    {
        var full = Path.IsPathRooted(path) ? path : TempPath();
        var directory = Path.GetDirectoryName(full);
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        File.WriteAllText(full, content);
        _tempPaths.Add(full);
        return full;
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-backuptest-{Guid.NewGuid():N}");
        _tempPaths.Add(path);
        return path;
    }

    private static string NonExistentPath() =>
        Path.Combine(Path.GetTempPath(), $"securetunnel-backuptest-missing-{Guid.NewGuid():N}");

    public void Dispose()
    {
        foreach (var p in _tempPaths)
        {
            try
            {
                if (Directory.Exists(p)) Directory.Delete(p, recursive: true);
                else if (File.Exists(p)) File.Delete(p);
            }
            catch { /* best-effort */ }
        }
    }
}
