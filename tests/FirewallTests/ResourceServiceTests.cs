using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class ResourceServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly ResourceService _service = new(new JsonFileResourceRepository(NullLogger<JsonFileResourceRepository>.Instance), NullLogger<ResourceService>.Instance);
    private readonly GatewayConfiguration _config;

    public ResourceServiceTests()
    {
        _config = TestConfigurationFactory.CreateValid();
        _config.ResourceStorePath = TempPath();
    }

    [Fact]
    public async Task AddAsync_Valid_Persists()
    {
        var result = await _service.AddAsync(_config, "Website", "10.20.0.10", Protocol.Tcp, 443, null, null, dryRun: false);

        Assert.True(result.Success);
        Assert.True(result.Resource!.Enabled);
        Assert.Single(await _service.ListAsync(_config));
    }

    [Fact]
    public async Task AddAsync_InvalidDestination_Rejected()
    {
        var result = await _service.AddAsync(_config, "Bad", "not-an-ip", Protocol.Tcp, 443, null, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Empty(await _service.ListAsync(_config));
    }

    [Fact]
    public async Task AddAsync_DryRun_DoesNotPersist()
    {
        var result = await _service.AddAsync(_config, "Website", "10.20.0.10", Protocol.Tcp, 443, null, null, dryRun: true);

        Assert.True(result.Success);
        Assert.False(File.Exists(_config.ResourceStorePath));
    }

    [Fact]
    public async Task DisableThenEnable_RoundTrips()
    {
        var add = await _service.AddAsync(_config, "Website", "10.20.0.10", Protocol.Tcp, 443, null, null, dryRun: false);

        var disable = await _service.DisableAsync(_config, add.Resource!.ResourceId, dryRun: false);
        Assert.True(disable.Success);
        Assert.False(disable.Resource!.Enabled);

        var enable = await _service.EnableAsync(_config, add.Resource.ResourceId, dryRun: false);
        Assert.True(enable.Success);
        Assert.True(enable.Resource!.Enabled);
    }

    [Fact]
    public async Task RemoveAsync_HardDeletes()
    {
        var add = await _service.AddAsync(_config, "Website", "10.20.0.10", Protocol.Tcp, 443, null, null, dryRun: false);

        var remove = await _service.RemoveAsync(_config, add.Resource!.ResourceId, dryRun: false);

        Assert.True(remove.Success);
        Assert.Null(await _service.GetAsync(_config, add.Resource.ResourceId));
    }

    [Fact]
    public async Task TransitionOnUnknownId_ReturnsNotFound()
    {
        var result = await _service.DisableAsync(_config, "resource-does-not-exist", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.NotFound, result.FailureKind);
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-ressvc-{Guid.NewGuid():N}.json");
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
