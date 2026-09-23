using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using Xunit;

namespace SecureTunnel.GatewayAgent.PeerTests;

public sealed class JsonFilePeerRepositoryTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly JsonFilePeerRepository _repository = new(NullLogger<JsonFilePeerRepository>.Instance);

    [Fact]
    public async Task LoadAllAsync_FileDoesNotExist_ReturnsEmptyListNotError()
    {
        var peers = await _repository.LoadAllAsync(TempPath());

        Assert.Empty(peers);
    }

    [Fact]
    public async Task SaveAllAsync_ThenLoadAllAsync_RoundTrips()
    {
        var path = TempPath();
        var peer = MakePeer("10.250.0.10");

        await _repository.SaveAllAsync(path, new[] { peer });
        var loaded = await _repository.LoadAllAsync(path);

        var reloaded = Assert.Single(loaded);
        Assert.Equal(peer.PeerId, reloaded.PeerId);
        Assert.Equal(peer.PublicKey, reloaded.PublicKey);
        Assert.Equal(peer.AssignedVpnIp, reloaded.AssignedVpnIp);
        Assert.Equal(peer.Status, reloaded.Status);
    }

    [Fact]
    public async Task SaveAllAsync_NeverWritesAPrivateKeyField()
    {
        // Structural guarantee: Peer has no private-key property at all, so nothing can
        // serialize one. This test fails loudly if a future change ever adds one without
        // updating this guard.
        var path = TempPath();
        await _repository.SaveAllAsync(path, new[] { MakePeer("10.250.0.10") });

        var json = await File.ReadAllTextAsync(path);

        Assert.DoesNotContain("PrivateKey", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task SaveAllAsync_LeavesNoTempFileBehindOnSuccess()
    {
        var path = TempPath();
        await _repository.SaveAllAsync(path, new[] { MakePeer("10.250.0.10") });

        var directory = Path.GetDirectoryName(path)!;
        var leftoverTempFiles = Directory.GetFiles(directory, Path.GetFileName(path) + ".tmp-*");

        Assert.Empty(leftoverTempFiles);
    }

    [Fact]
    public async Task SaveAllAsync_Overwrite_ReplacesContentAtomically()
    {
        var path = TempPath();
        await _repository.SaveAllAsync(path, new[] { MakePeer("10.250.0.10", peerId: "peer-a") });
        await _repository.SaveAllAsync(path, new[] { MakePeer("10.250.0.11", peerId: "peer-b") });

        var loaded = await _repository.LoadAllAsync(path);

        var only = Assert.Single(loaded);
        Assert.Equal("peer-b", only.PeerId);
    }

    [Fact]
    public async Task LoadAllAsync_MalformedJson_ThrowsCorruptExceptionNotSilentReset()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, "{ this is not valid json [[[");

        await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    [Fact]
    public async Task LoadAllAsync_EmptyFile_ThrowsCorruptExceptionNotSilentReset()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, string.Empty);

        await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    [Fact]
    public async Task LoadAllAsync_DuplicatePeerId_ThrowsCorruptException()
    {
        var path = TempPath();
        var json = """
            [
              {"peerId":"peer-1","name":"a","publicKey":"key-a","assignedVpnIp":"10.250.0.10","status":"Active","createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z","allowedIps":[]},
              {"peerId":"peer-1","name":"b","publicKey":"key-b","assignedVpnIp":"10.250.0.11","status":"Active","createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z","allowedIps":[]}
            ]
            """;
        await File.WriteAllTextAsync(path, json);

        var ex = await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.LoadAllAsync(path));
        Assert.Contains("duplicate PeerId", ex.Message);
    }

    [Fact]
    public async Task LoadAllAsync_DuplicatePublicKey_ThrowsCorruptException()
    {
        var path = TempPath();
        var json = """
            [
              {"peerId":"peer-1","name":"a","publicKey":"same-key","assignedVpnIp":"10.250.0.10","status":"Active","createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z","allowedIps":[]},
              {"peerId":"peer-2","name":"b","publicKey":"same-key","assignedVpnIp":"10.250.0.11","status":"Active","createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z","allowedIps":[]}
            ]
            """;
        await File.WriteAllTextAsync(path, json);

        var ex = await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.LoadAllAsync(path));
        Assert.Contains("duplicate PublicKey", ex.Message);
    }

    [Fact]
    public async Task LoadAllAsync_MissingRequiredField_ThrowsCorruptException()
    {
        var path = TempPath();
        // publicKey is missing entirely.
        var json = """[{"peerId":"peer-1","name":"a","assignedVpnIp":"10.250.0.10","status":"Active","createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z","allowedIps":[]}]""";
        await File.WriteAllTextAsync(path, json);

        await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    [Fact]
    public async Task SaveAllAsync_DuplicatePeerIdInMemory_ThrowsBeforeWriting()
    {
        var path = TempPath();
        var peers = new[] { MakePeer("10.250.0.10", peerId: "peer-dup"), MakePeer("10.250.0.11", peerId: "peer-dup") };

        await Assert.ThrowsAsync<PeerRegistryCorruptException>(() => _repository.SaveAllAsync(path, peers));
        Assert.False(File.Exists(path));
    }

    private static Peer MakePeer(string ip, string? peerId = null) => new()
    {
        PeerId = peerId ?? $"peer-{Guid.NewGuid():N}"[..12],
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()) + ip, // unique-ish per call
        AssignedVpnIp = ip,
        Status = PeerStatus.Active,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-peertest-{Guid.NewGuid():N}.json");
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { /* best-effort */ }
        }
    }
}
