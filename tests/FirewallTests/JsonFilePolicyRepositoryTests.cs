using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class JsonFilePolicyRepositoryTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly JsonFilePolicyRepository _repository = new(NullLogger<JsonFilePolicyRepository>.Instance);

    [Fact]
    public async Task LoadAllAsync_FileDoesNotExist_ReturnsEmptyList()
    {
        var policies = await _repository.LoadAllAsync(TempPath());
        Assert.Empty(policies);
    }

    [Fact]
    public async Task SaveAllAsync_ThenLoadAllAsync_RoundTrips()
    {
        var path = TempPath();
        var policy = MakePolicy("rule-1", "peer-a", "resource-a");

        await _repository.SaveAllAsync(path, new[] { policy });
        var loaded = await _repository.LoadAllAsync(path);

        var reloaded = Assert.Single(loaded);
        Assert.Equal(policy.RuleId, reloaded.RuleId);
        Assert.Equal(policy.PeerId, reloaded.PeerId);
        Assert.Equal(policy.ResourceId, reloaded.ResourceId);
    }

    [Fact]
    public async Task LoadAllAsync_DuplicateRuleId_ThrowsCorruptException()
    {
        var path = TempPath();
        var json = """
            [
              {"ruleId":"rule-1","peerId":"peer-a","resourceId":"resource-a","enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"},
              {"ruleId":"rule-1","peerId":"peer-b","resourceId":"resource-b","enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"}
            ]
            """;
        await File.WriteAllTextAsync(path, json);

        var ex = await Assert.ThrowsAsync<PolicyRegistryCorruptException>(() => _repository.LoadAllAsync(path));
        Assert.Contains("duplicate RuleId", ex.Message);
    }

    [Fact]
    public async Task LoadAllAsync_DuplicatePermission_ThrowsCorruptException()
    {
        var path = TempPath();
        var json = """
            [
              {"ruleId":"rule-1","peerId":"peer-a","resourceId":"resource-a","enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"},
              {"ruleId":"rule-2","peerId":"peer-a","resourceId":"resource-a","enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"}
            ]
            """;
        await File.WriteAllTextAsync(path, json);

        var ex = await Assert.ThrowsAsync<PolicyRegistryCorruptException>(() => _repository.LoadAllAsync(path));
        Assert.Contains("duplicate permission", ex.Message);
    }

    [Fact]
    public async Task SaveAllAsync_DuplicatePermissionInMemory_ThrowsBeforeWriting()
    {
        var path = TempPath();
        var policies = new[] { MakePolicy("rule-1", "peer-a", "resource-a"), MakePolicy("rule-2", "peer-a", "resource-a") };

        await Assert.ThrowsAsync<PolicyRegistryCorruptException>(() => _repository.SaveAllAsync(path, policies));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task LoadAllAsync_EmptyFile_ThrowsCorruptException()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, string.Empty);

        await Assert.ThrowsAsync<PolicyRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    private static AccessPolicy MakePolicy(string ruleId, string peerId, string resourceId) => new()
    {
        RuleId = ruleId,
        PeerId = peerId,
        ResourceId = resourceId,
        Enabled = true,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-poltest-{Guid.NewGuid():N}.json");
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
