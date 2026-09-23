using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class JsonFileResourceRepositoryTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly JsonFileResourceRepository _repository = new(NullLogger<JsonFileResourceRepository>.Instance);

    [Fact]
    public async Task LoadAllAsync_FileDoesNotExist_ReturnsEmptyList()
    {
        var resources = await _repository.LoadAllAsync(TempPath());
        Assert.Empty(resources);
    }

    [Fact]
    public async Task SaveAllAsync_ThenLoadAllAsync_RoundTrips()
    {
        var path = TempPath();
        var resource = MakeResource("resource-a");

        await _repository.SaveAllAsync(path, new[] { resource });
        var loaded = await _repository.LoadAllAsync(path);

        var reloaded = Assert.Single(loaded);
        Assert.Equal(resource.ResourceId, reloaded.ResourceId);
        Assert.Equal(resource.Destination, reloaded.Destination);
        Assert.Equal(resource.Protocol, reloaded.Protocol);
    }

    [Fact]
    public async Task SaveAllAsync_Overwrite_ReplacesContentAtomically()
    {
        var path = TempPath();
        await _repository.SaveAllAsync(path, new[] { MakeResource("resource-a") });
        await _repository.SaveAllAsync(path, new[] { MakeResource("resource-b") });

        var loaded = await _repository.LoadAllAsync(path);

        var only = Assert.Single(loaded);
        Assert.Equal("resource-b", only.ResourceId);
    }

    [Fact]
    public async Task LoadAllAsync_MalformedJson_ThrowsCorruptException()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, "{ not valid [[[");

        await Assert.ThrowsAsync<ResourceRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    [Fact]
    public async Task LoadAllAsync_EmptyFile_ThrowsCorruptException()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, string.Empty);

        await Assert.ThrowsAsync<ResourceRegistryCorruptException>(() => _repository.LoadAllAsync(path));
    }

    [Fact]
    public async Task LoadAllAsync_DuplicateResourceId_ThrowsCorruptException()
    {
        var path = TempPath();
        var json = """
            [
              {"resourceId":"r1","name":"a","destination":"10.20.0.10","protocol":"Tcp","port":443,"enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"},
              {"resourceId":"r1","name":"b","destination":"10.20.0.11","protocol":"Tcp","port":443,"enabled":true,"createdAtUtc":"2026-01-01T00:00:00Z","updatedAtUtc":"2026-01-01T00:00:00Z"}
            ]
            """;
        await File.WriteAllTextAsync(path, json);

        var ex = await Assert.ThrowsAsync<ResourceRegistryCorruptException>(() => _repository.LoadAllAsync(path));
        Assert.Contains("duplicate ResourceId", ex.Message);
    }

    [Fact]
    public async Task SaveAllAsync_DuplicateResourceIdInMemory_ThrowsBeforeWriting()
    {
        var path = TempPath();
        var resources = new[] { MakeResource("dup"), MakeResource("dup") };

        await Assert.ThrowsAsync<ResourceRegistryCorruptException>(() => _repository.SaveAllAsync(path, resources));
        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task SaveAllAsync_LeavesNoTempFileBehindOnSuccess()
    {
        var path = TempPath();
        await _repository.SaveAllAsync(path, new[] { MakeResource("r1") });

        var directory = Path.GetDirectoryName(path)!;
        Assert.Empty(Directory.GetFiles(directory, Path.GetFileName(path) + ".tmp-*"));
    }

    private static ProtectedResource MakeResource(string id) => new()
    {
        ResourceId = id,
        Name = "test",
        Destination = "10.20.0.10",
        Protocol = Protocol.Tcp,
        Port = 443,
        Enabled = true,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-restest-{Guid.NewGuid():N}.json");
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
