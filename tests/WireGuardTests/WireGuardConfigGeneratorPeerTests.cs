using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;
using Xunit;

namespace SecureTunnel.GatewayAgent.WireGuardTests;

/// <summary>
/// Phase 3: verifies WireGuardConfigGenerator's integration with the Peer set - see
/// docs/architecture.md 第七節 "WireGuard Configuration Integration".
/// </summary>
public sealed class WireGuardConfigGeneratorPeerTests : IDisposable
{
    private readonly List<string> _tempPaths = new();
    private readonly WireGuardConfigGenerator _generator = new(new GatewayConfigurationValidator(), NullLogger<WireGuardConfigGenerator>.Instance);

    [Fact]
    public async Task GenerateAsync_ActivePeers_AreRenderedAsPeerBlocks()
    {
        var config = ValidConfigWithKey();
        var peer = MakePeer("10.250.0.10");

        var result = await _generator.GenerateAsync(config, new[] { peer }, new ConfigGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.Contains("[Peer]", result.RenderedForReview);
        Assert.Contains(peer.PublicKey, result.RenderedForReview);
        Assert.Contains("AllowedIPs = 10.250.0.10/32", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_NoPeers_StillSucceedsWithInterfaceOnly()
    {
        var config = ValidConfigWithKey();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.DoesNotContain("[Peer]", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_NonActivePeerInList_Rejected()
    {
        var config = ValidConfigWithKey();
        var disabledPeer = MakePeer("10.250.0.10", PeerStatus.Disabled);

        var result = await _generator.GenerateAsync(config, new[] { disabledPeer }, new ConfigGenerationOptions { DryRun = true });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Message.Contains("Active"));
    }

    [Fact]
    public async Task GenerateAsync_DuplicatePublicKeyAcrossPeers_Rejected()
    {
        var config = ValidConfigWithKey();
        var peerA = MakePeer("10.250.0.10");
        var peerB = MakePeer("10.250.0.11");
        peerB.PublicKey = peerA.PublicKey; // force duplicate

        var result = await _generator.GenerateAsync(config, new[] { peerA, peerB }, new ConfigGenerationOptions { DryRun = true });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Message.Contains("Duplicate public key"));
    }

    [Fact]
    public async Task GenerateAsync_DuplicateAllowedIpAcrossPeers_Rejected()
    {
        var config = ValidConfigWithKey();
        var peerA = MakePeer("10.250.0.10");
        var peerB = MakePeer("10.250.0.11");
        peerB.AllowedIps = new List<string> { "10.250.0.10/32" }; // collides with peerA's AllowedIPs

        var result = await _generator.GenerateAsync(config, new[] { peerA, peerB }, new ConfigGenerationOptions { DryRun = true });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Message.Contains("already assigned to another peer"));
    }

    [Fact]
    public async Task GenerateAsync_WithPeers_NeverLeaksServerPrivateKeyInReview()
    {
        var config = ValidConfigWithKey("REAL_SERVER_PRIVATE_KEY_VALUE=");
        var peer = MakePeer("10.250.0.10");

        var result = await _generator.GenerateAsync(config, new[] { peer }, new ConfigGenerationOptions { DryRun = true });

        Assert.DoesNotContain("REAL_SERVER_PRIVATE_KEY_VALUE", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_WrittenFile_ContainsPeerBlockAndServerKey()
    {
        var config = ValidConfigWithKey("REAL_SERVER_KEY=");
        var peer = MakePeer("10.250.0.10");
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, new[] { peer }, new ConfigGenerationOptions { OutputPath = outputPath });

        Assert.True(result.Success);
        var written = await File.ReadAllTextAsync(outputPath);
        Assert.Contains("REAL_SERVER_KEY=", written);
        Assert.Contains(peer.PublicKey, written);
    }

    private GatewayConfiguration ValidConfigWithKey(string keyContent = "TEST_KEY=")
    {
        var config = TestConfigurationFactory.CreateValid();
        var keyPath = TempPath();
        File.WriteAllText(keyPath, keyContent);
        config.WireGuard.PrivateKeyPath = keyPath;
        return config;
    }

    private static Peer MakePeer(string ip, PeerStatus status = PeerStatus.Active)
    {
        var bytes = new byte[32];
        Random.Shared.NextBytes(bytes);
        return new Peer
        {
            PeerId = $"peer-{Guid.NewGuid():N}"[..12],
            Name = "test",
            PublicKey = Convert.ToBase64String(bytes),
            AssignedVpnIp = ip,
            Status = status,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            AllowedIps = new List<string> { $"{ip}/32" }
        };
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-wgpeertest-{Guid.NewGuid():N}");
        _tempPaths.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var p in _tempPaths)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { /* best-effort */ }
        }
    }
}
