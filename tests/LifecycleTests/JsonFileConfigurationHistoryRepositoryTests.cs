using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;
using Xunit;

namespace SecureTunnel.GatewayAgent.LifecycleTests;

public sealed class JsonFileConfigurationHistoryRepositoryTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly JsonFileConfigurationHistoryRepository _repository = new(NullLogger<JsonFileConfigurationHistoryRepository>.Instance);

    [Fact]
    public async Task LoadAsync_FileDoesNotExist_ReturnsFreshEmptyHistory()
    {
        var history = await _repository.LoadAsync(TempPath());

        Assert.Empty(history.Versions);
        Assert.Null(history.ActiveVersion);
        Assert.Null(history.LastKnownGoodVersion);
    }

    [Fact]
    public async Task SaveAsync_ThenLoadAsync_RoundTrips()
    {
        var path = TempPath();
        var history = new ConfigurationHistory { ActiveVersion = 1, LastKnownGoodVersion = null };
        history.Versions.Add(MakeSnapshot(1, ConfigurationState.Active));

        await _repository.SaveAsync(path, history);
        var loaded = await _repository.LoadAsync(path);

        Assert.Equal(1, loaded.ActiveVersion);
        var v1 = Assert.Single(loaded.Versions);
        Assert.Equal(ConfigurationState.Active, v1.State);
    }

    [Fact]
    public async Task LoadAsync_EmptyFile_ThrowsCorruptException()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, string.Empty);

        await Assert.ThrowsAsync<ConfigurationHistoryCorruptException>(() => _repository.LoadAsync(path));
    }

    [Fact]
    public async Task LoadAsync_MalformedJson_ThrowsCorruptException()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, "{ not valid [[[");

        await Assert.ThrowsAsync<ConfigurationHistoryCorruptException>(() => _repository.LoadAsync(path));
    }

    [Fact]
    public async Task SaveAsync_DuplicateVersionNumbers_ThrowsBeforeWriting()
    {
        var path = TempPath();
        var history = new ConfigurationHistory();
        history.Versions.Add(MakeSnapshot(1, ConfigurationState.Active));
        history.Versions.Add(MakeSnapshot(1, ConfigurationState.ValidationFailed));

        await Assert.ThrowsAsync<ConfigurationHistoryCorruptException>(() => _repository.SaveAsync(path, history));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task SaveAsync_NeverWritesAPrivateKeyField()
    {
        var path = TempPath();
        var history = new ConfigurationHistory();
        history.Versions.Add(MakeSnapshot(1, ConfigurationState.Active));

        await _repository.SaveAsync(path, history);

        var json = await File.ReadAllTextAsync(path);
        Assert.DoesNotContain("PrivateKey", json, StringComparison.OrdinalIgnoreCase);
    }

    private static ConfigurationSnapshot MakeSnapshot(int version, ConfigurationState state) => new()
    {
        Version = version,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        SourceReason = "test",
        ContentHash = "deadbeef",
        State = state,
        Peers = Array.Empty<Peer>(),
        Resources = Array.Empty<ProtectedResource>(),
        Policies = Array.Empty<AccessPolicy>(),
        EffectiveWireGuardPeerCount = 0,
        EffectiveFirewallRuleCount = 0
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-history-{Guid.NewGuid():N}.json");
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
