using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Peer registry persisted as a single JSON array file. Chosen over YAML/SQLite for
/// Phase 3 because: it is the simplest reliable option for the current single-Gateway,
/// single-operator MVP; System.Text.Json gives us schema validation for free via
/// required/nullable properties; and a single file is trivial to back up (see
/// docs/operations-guide.md). SQLite is the natural next step if concurrent writers or
/// query needs grow - documented as a Known Limitation, not implemented here.
///
/// Concurrency: this repository does NOT implement cross-process locking. Two concurrent
/// `securetunnel-gateway peer ...` invocations against the same store can race (last
/// writer wins). Acceptable for the current single-operator CLI MVP; documented in
/// docs/security-model.md.
/// </summary>
public sealed class JsonFilePeerRepository : IPeerRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        // camelCase to match this project's other config/data files (gateway.yaml etc.)
        // and docs/configuration-guide.md's field tables.
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        // Tolerant on read (an operator hand-editing the file, or a future casing change,
        // shouldn't turn into a spurious "corrupt registry" failure); System.Text.Json's
        // own default (exact-case) would otherwise silently leave `required` properties
        // unset and throw a generic JsonException instead of our specific validation.
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ILogger<JsonFilePeerRepository> _logger;

    public JsonFilePeerRepository(ILogger<JsonFilePeerRepository> logger)
    {
        _logger = logger;
    }

    public async Task<IReadOnlyList<Peer>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(storePath))
        {
            return Array.Empty<Peer>();
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(storePath, cancellationToken);
        }
        catch (IOException ex)
        {
            throw new PeerRegistryCorruptException($"Could not read peer registry '{storePath}': {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            // An empty file is ambiguous (truncated write? deliberately emptied?) - fail
            // closed rather than silently treating it as "no peers", per docs/security-model.md.
            throw new PeerRegistryCorruptException($"Peer registry '{storePath}' exists but is empty. Refusing to treat this as an empty registry - restore from backup or delete the file to start fresh deliberately.");
        }

        List<Peer>? peers;
        try
        {
            peers = JsonSerializer.Deserialize<List<Peer>>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new PeerRegistryCorruptException($"Peer registry '{storePath}' contains invalid JSON: {ex.Message}");
        }

        if (peers is null)
        {
            throw new PeerRegistryCorruptException($"Peer registry '{storePath}' deserialized to null.");
        }

        ValidateNoDuplicates(peers, storePath);

        return peers;
    }

    public async Task SaveAllAsync(string storePath, IReadOnlyList<Peer> peers, CancellationToken cancellationToken = default)
    {
        ValidateNoDuplicates(peers, storePath);

        var directory = Path.GetDirectoryName(storePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Atomic write: write to a temp file in the same directory, then rename over the
        // target. A crash mid-write leaves the temp file, never a half-written store.json.
        var tempPath = storePath + $".tmp-{Guid.NewGuid():N}";
        var json = JsonSerializer.Serialize(peers, SerializerOptions);

        await File.WriteAllTextAsync(tempPath, json, cancellationToken);

        try
        {
            File.Move(tempPath, storePath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { /* best-effort cleanup */ }
            }
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(storePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        _logger.LogInformation("Saved peer registry with {Count} peer(s) to {Path}", peers.Count, storePath);
    }

    private static void ValidateNoDuplicates(IReadOnlyList<Peer> peers, string storePath)
    {
        var duplicateIds = peers.GroupBy(p => p.PeerId, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicateIds is not null)
        {
            throw new PeerRegistryCorruptException($"Peer registry '{storePath}' contains duplicate PeerId '{duplicateIds.Key}'.");
        }

        var duplicateKeys = peers.GroupBy(p => p.PublicKey, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicateKeys is not null)
        {
            throw new PeerRegistryCorruptException($"Peer registry '{storePath}' contains duplicate PublicKey (peer ids: {string.Join(", ", duplicateKeys.Select(p => p.PeerId))}).");
        }

        foreach (var peer in peers)
        {
            if (string.IsNullOrWhiteSpace(peer.PeerId) || string.IsNullOrWhiteSpace(peer.PublicKey) || string.IsNullOrWhiteSpace(peer.AssignedVpnIp))
            {
                throw new PeerRegistryCorruptException($"Peer registry '{storePath}' contains a record with a missing required field (PeerId/PublicKey/AssignedVpnIp).");
            }
        }
    }
}
