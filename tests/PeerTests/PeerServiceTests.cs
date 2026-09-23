using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.PeerTests;

/// <summary>
/// Uses the real JsonFilePeerRepository and Ipv4VpnIpAllocator (both already covered by
/// their own dedicated test files) against a temp file, rather than mocks - this is
/// deliberately closer to an integration test for the orchestration logic itself
/// (validation -> allocation -> persistence ordering, dry-run, status transition rules).
/// </summary>
public sealed class PeerServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly PeerService _service;
    private readonly GatewayConfiguration _config;

    public PeerServiceTests()
    {
        _service = new PeerService(
            new JsonFilePeerRepository(NullLogger<JsonFilePeerRepository>.Instance),
            new Ipv4VpnIpAllocator(),
            NullLogger<PeerService>.Instance);

        _config = TestConfigurationFactory.CreateValid();
        _config.PeerStorePath = TempPath();
    }

    // --- Add: valid ---

    [Fact]
    public async Task AddAsync_Valid_PersistsActivePeerWithAllocatedIp()
    {
        var result = await _service.AddAsync(_config, "Alice Laptop", ValidKey(1), "desc", null, dryRun: false);

        Assert.True(result.Success);
        Assert.Equal(PeerStatus.Active, result.Peer!.Status);
        Assert.Equal("10.250.0.10", result.Peer.AssignedVpnIp);

        var listed = await _service.ListAsync(_config);
        Assert.Single(listed);
    }

    [Fact]
    public async Task AddAsync_DryRun_DoesNotPersist()
    {
        var result = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.False(File.Exists(_config.PeerStorePath));
    }

    // --- Add: invalid name ---

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task AddAsync_InvalidName_Rejected(string name)
    {
        var result = await _service.AddAsync(_config, name, ValidKey(1), null, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
        Assert.False(File.Exists(_config.PeerStorePath));
    }

    // --- Add: invalid public key ---

    [Fact]
    public async Task AddAsync_InvalidPublicKey_Rejected()
    {
        var result = await _service.AddAsync(_config, "Alice", "not-a-key", null, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
    }

    // --- Add: duplicate public key ---

    [Fact]
    public async Task AddAsync_DuplicatePublicKey_Rejected()
    {
        await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var result = await _service.AddAsync(_config, "Alice's Second Device", ValidKey(1), null, null, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.ValidationFailed, result.FailureKind);
    }

    [Fact]
    public async Task AddAsync_PublicKeyOfRevokedPeer_StillRejected()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);
        await _service.RevokeAsync(_config, add.Peer!.PeerId, dryRun: false);

        var result = await _service.AddAsync(_config, "New Device, Same Key", ValidKey(1), null, null, dryRun: false);

        Assert.False(result.Success, "a revoked peer's public key must never be silently reusable");
    }

    // --- Status transitions ---

    [Fact]
    public async Task DisableThenEnable_RoundTrips()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var disable = await _service.DisableAsync(_config, add.Peer!.PeerId, dryRun: false);
        Assert.True(disable.Success);
        Assert.Equal(PeerStatus.Disabled, disable.Peer!.Status);

        var effectiveAfterDisable = await _service.GetEffectivePeersAsync(_config);
        Assert.Empty(effectiveAfterDisable);

        var enable = await _service.EnableAsync(_config, add.Peer.PeerId, dryRun: false);
        Assert.True(enable.Success);
        Assert.Equal(PeerStatus.Active, enable.Peer!.Status);
        Assert.Equal(add.Peer.AssignedVpnIp, enable.Peer.AssignedVpnIp); // same IP retained across Disable/Enable

        var effectiveAfterEnable = await _service.GetEffectivePeersAsync(_config);
        Assert.Single(effectiveAfterEnable);
    }

    [Fact]
    public async Task Revoke_ExcludesFromEffectiveConfig_AndCannotBeReEnabled()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var revoke = await _service.RevokeAsync(_config, add.Peer!.PeerId, dryRun: false);
        Assert.True(revoke.Success);
        Assert.Equal(PeerStatus.Revoked, revoke.Peer!.Status);

        Assert.Empty(await _service.GetEffectivePeersAsync(_config));

        var reEnable = await _service.EnableAsync(_config, add.Peer.PeerId, dryRun: false);
        Assert.False(reEnable.Success, "Enable must not silently reactivate a Revoked peer");
        Assert.Equal(PeerOperationFailureKind.Conflict, reEnable.FailureKind);
    }

    [Fact]
    public async Task Remove_IsIdempotent_AndExcludesFromEffectiveConfig()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var remove1 = await _service.RemoveAsync(_config, add.Peer!.PeerId, dryRun: false);
        Assert.True(remove1.Success);
        Assert.Equal(PeerStatus.Removed, remove1.Peer!.Status);

        var remove2 = await _service.RemoveAsync(_config, add.Peer.PeerId, dryRun: false);
        Assert.True(remove2.Success, "removing an already-Removed peer should be a safe no-op, not an error");

        // Soft-delete: the record still exists (audit trail retained), just excluded from effective config.
        Assert.NotNull(await _service.GetAsync(_config, add.Peer.PeerId));
        Assert.Empty(await _service.GetEffectivePeersAsync(_config));
    }

    [Fact]
    public async Task Disable_OnAlreadyRevokedPeer_Rejected()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);
        await _service.RevokeAsync(_config, add.Peer!.PeerId, dryRun: false);

        var disable = await _service.DisableAsync(_config, add.Peer.PeerId, dryRun: false);

        Assert.False(disable.Success);
        Assert.Equal(PeerOperationFailureKind.Conflict, disable.FailureKind);
    }

    [Fact]
    public async Task TransitionOnUnknownPeerId_ReturnsNotFound()
    {
        var result = await _service.DisableAsync(_config, "peer-does-not-exist", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(PeerOperationFailureKind.NotFound, result.FailureKind);
    }

    [Fact]
    public async Task Disable_DryRun_DoesNotPersistChange()
    {
        var add = await _service.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var disable = await _service.DisableAsync(_config, add.Peer!.PeerId, dryRun: true);
        Assert.True(disable.Success);
        Assert.True(disable.DryRun);

        var stillActive = await _service.GetAsync(_config, add.Peer.PeerId);
        Assert.Equal(PeerStatus.Active, stillActive!.Status);
    }

    // --- GetEffectivePeersAsync ---

    [Fact]
    public async Task GetEffectivePeersAsync_OnlyIncludesActive()
    {
        var active = await _service.AddAsync(_config, "Active", ValidKey(1), null, null, dryRun: false);
        var toDisable = await _service.AddAsync(_config, "ToDisable", ValidKey(2), null, null, dryRun: false);
        await _service.DisableAsync(_config, toDisable.Peer!.PeerId, dryRun: false);

        var effective = await _service.GetEffectivePeersAsync(_config);

        var only = Assert.Single(effective);
        Assert.Equal(active.Peer!.PeerId, only.PeerId);
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-peersvc-{Guid.NewGuid():N}.json");
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
