using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class PolicyServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly GatewayConfiguration _config;
    private readonly PeerService _peerService;
    private readonly ResourceService _resourceService;
    private readonly PolicyService _policyService;

    public PolicyServiceTests()
    {
        _config = TestConfigurationFactory.CreateValid();
        _config.PeerStorePath = TempPath();
        _config.ResourceStorePath = TempPath();
        _config.PolicyStorePath = TempPath();

        _peerService = new PeerService(new JsonFilePeerRepository(NullLogger<JsonFilePeerRepository>.Instance), new Ipv4VpnIpAllocator(), NullLogger<PeerService>.Instance);
        _resourceService = new ResourceService(new JsonFileResourceRepository(NullLogger<JsonFileResourceRepository>.Instance), NullLogger<ResourceService>.Instance);
        _policyService = new PolicyService(new JsonFilePolicyRepository(NullLogger<JsonFilePolicyRepository>.Instance), _peerService, _resourceService, NullLogger<PolicyService>.Instance);
    }

    [Fact]
    public async Task AddAsync_ValidPeerAndResource_Persists()
    {
        var peer = await AddActivePeerAsync();
        var resource = await AddEnabledResourceAsync();

        var result = await _policyService.AddAsync(_config, peer, resource, null, dryRun: false);

        Assert.True(result.Success);
        Assert.Single(await _policyService.ListAsync(_config));
    }

    [Fact]
    public async Task AddAsync_UnknownPeer_Rejected()
    {
        var resource = await AddEnabledResourceAsync();

        var result = await _policyService.AddAsync(_config, "peer-does-not-exist", resource, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
    }

    [Fact]
    public async Task AddAsync_UnknownResource_Rejected()
    {
        var peer = await AddActivePeerAsync();

        var result = await _policyService.AddAsync(_config, peer, "resource-does-not-exist", null, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
    }

    [Fact]
    public async Task AddAsync_DuplicatePermission_Rejected()
    {
        var peer = await AddActivePeerAsync();
        var resource = await AddEnabledResourceAsync();
        await _policyService.AddAsync(_config, peer, resource, null, dryRun: false);

        var result = await _policyService.AddAsync(_config, peer, resource, "second attempt", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
    }

    [Fact]
    public async Task AddAsync_DisabledPeerReference_SucceedsWithWarning()
    {
        var peerAdd = await _peerService.AddAsync(_config, "Disabled Peer", ValidKey(1), null, null, dryRun: false);
        await _peerService.DisableAsync(_config, peerAdd.Peer!.PeerId, dryRun: false);
        var resource = await AddEnabledResourceAsync();

        var result = await _policyService.AddAsync(_config, peerAdd.Peer.PeerId, resource, null, dryRun: false);

        Assert.True(result.Success, "a policy referencing a currently-disabled peer is well-formed, not an error");
        Assert.Contains(result.Issues, i => i.Severity == ValidationSeverity.Warning);
    }

    [Fact]
    public async Task DisableThenEnable_RoundTrips()
    {
        var peer = await AddActivePeerAsync();
        var resource = await AddEnabledResourceAsync();
        var add = await _policyService.AddAsync(_config, peer, resource, null, dryRun: false);

        var disable = await _policyService.DisableAsync(_config, add.Policy!.RuleId, dryRun: false);
        Assert.True(disable.Success);
        Assert.False(disable.Policy!.Enabled);

        var enable = await _policyService.EnableAsync(_config, add.Policy.RuleId, dryRun: false);
        Assert.True(enable.Success);
        Assert.True(enable.Policy!.Enabled);
    }

    [Fact]
    public async Task RemoveAsync_HardDeletes_AndFreesPermissionForReuse()
    {
        var peer = await AddActivePeerAsync();
        var resource = await AddEnabledResourceAsync();
        var add = await _policyService.AddAsync(_config, peer, resource, null, dryRun: false);

        var remove = await _policyService.RemoveAsync(_config, add.Policy!.RuleId, dryRun: false);
        Assert.True(remove.Success);

        var readd = await _policyService.AddAsync(_config, peer, resource, null, dryRun: false);
        Assert.True(readd.Success, "removing a policy must free up the peer-resource permission for a new policy");
    }

    private async Task<string> AddActivePeerAsync()
    {
        var result = await _peerService.AddAsync(_config, "Test Peer", ValidKey(Random.Shared.Next()), null, null, dryRun: false);
        return result.Peer!.PeerId;
    }

    private async Task<string> AddEnabledResourceAsync()
    {
        var result = await _resourceService.AddAsync(_config, "Test Resource", "10.20.0.10", Protocol.Tcp, 443, null, null, dryRun: false);
        return result.Resource!.ResourceId;
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-polsvc-{Guid.NewGuid():N}.json");
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
