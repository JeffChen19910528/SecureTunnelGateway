using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class FirewallRuleGeneratorTests : IDisposable
{
    private readonly List<string> _tempPaths = new();
    private readonly FirewallRuleGenerator _generator = new(NullLogger<FirewallRuleGenerator>.Instance);

    [Fact]
    public async Task GenerateAsync_ActivePeerEnabledResourceEnabledPolicy_ProducesOneEffectiveRule()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.Single(result.EffectiveRules);
        Assert.Equal("10.250.0.10", result.EffectiveRules[0].PeerVpnIp);
        Assert.Equal("10.20.0.10", result.EffectiveRules[0].Destination);
        Assert.Contains("ip saddr 10.250.0.10 ip daddr 10.20.0.10 tcp dport 443 accept", result.RenderedForReview);
    }

    [Theory]
    [InlineData(PeerStatus.Pending)]
    [InlineData(PeerStatus.Disabled)]
    [InlineData(PeerStatus.Revoked)]
    [InlineData(PeerStatus.Removed)]
    public async Task GenerateAsync_NonActivePeer_ExcludedFromEffectiveRules(PeerStatus status)
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", status, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.Empty(result.EffectiveRules);
    }

    [Fact]
    public async Task GenerateAsync_DisabledResource_Excluded()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443, enabled: false);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.Empty(result.EffectiveRules);
    }

    [Fact]
    public async Task GenerateAsync_DisabledPolicy_Excluded()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: false);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.Empty(result.EffectiveRules);
    }

    [Fact]
    public async Task GenerateAsync_UnknownPeerOrResourceReference_ExcludedNotError()
    {
        var config = TestConfigurationFactory.CreateValid();
        var policy = MakePolicy("rule-1", "peer-does-not-exist", "resource-does-not-exist", enabled: true);

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.True(result.Success, "an unknown reference is excluded from effective rules, not a generation error - see docs/firewall-model.md");
        Assert.Empty(result.EffectiveRules);
    }

    [Fact]
    public async Task GenerateAsync_EmptyEverything_StillSucceedsWithDefaultDenyOnly()
    {
        var config = TestConfigurationFactory.CreateValid();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), new FirewallGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.Empty(result.EffectiveRules);
        Assert.Contains("policy drop", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_RenderedRuleset_AlwaysHasForwardPolicyDrop()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.Contains("type filter hook forward priority 0; policy drop;", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_NeverProducesAnAllowAllRule()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.DoesNotContain("ip saddr 0.0.0.0/0", result.RenderedForReview);
        Assert.DoesNotContain("policy accept", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_TwoPeers_DeterministicOutputRegardlessOfInputOrder()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peerA = MakePeer("peer-a", PeerStatus.Active, "10.250.0.10");
        var peerB = MakePeer("peer-b", PeerStatus.Active, "10.250.0.11");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policyA = MakePolicy("rule-a", "peer-a", "resource-1", enabled: true);
        var policyB = MakePolicy("rule-b", "peer-b", "resource-1", enabled: true);

        var result1 = await _generator.GenerateAsync(config, new[] { peerA, peerB }, new[] { resource }, new[] { policyA, policyB }, new FirewallGenerationOptions { DryRun = true });
        var result2 = await _generator.GenerateAsync(config, new[] { peerB, peerA }, new[] { resource }, new[] { policyB, policyA }, new FirewallGenerationOptions { DryRun = true });

        Assert.Equal(result1.RenderedForReview, result2.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_PortRange_RendersRangeSyntax()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 8000, portEnd: 8010);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.Contains("tcp dport 8000-8010 accept", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_UdpProtocol_RendersUdpSyntax()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 53, protocol: Protocol.Udp);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.Contains("udp dport 53 accept", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_NatMode_GeneratesMasqueradeScopedToVpnAndProtectedNetwork()
    {
        var config = TestConfigurationFactory.CreateValid(); // routing.mode = "nat", protectedNetworks = [10.20.0.0/24]

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), new FirewallGenerationOptions { DryRun = true });

        Assert.Contains("ip saddr 10.250.0.0/24 ip daddr 10.20.0.0/24 masquerade", result.RenderedForReview);
        Assert.DoesNotContain("ip saddr 0.0.0.0/0", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_MasqueradeRule_AppearsInPostroutingNotForward()
    {
        var config = TestConfigurationFactory.CreateValid();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), new FirewallGenerationOptions { DryRun = true });

        var forwardChainText = result.RenderedForReview[..result.RenderedForReview.IndexOf("chain postrouting", StringComparison.Ordinal)];
        Assert.DoesNotContain("masquerade", forwardChainText);
    }

    /// <summary>
    /// Phase 7 security review: proves IPv6 forwarded traffic cannot bypass authorization.
    /// `table inet securetunnel` uses nftables' combined "inet" family, which processes BOTH
    /// IPv4 and IPv6 packets through the same `forward` chain and its `policy drop`. Since
    /// every generated match/accept rule uses only `ip saddr`/`ip daddr` (IPv4-specific)
    /// matchers and the ruleset never emits an `ip6` matcher, no IPv6 packet can ever match
    /// an accept rule - it structurally falls through to the chain's default deny. This test
    /// locks that property in as a regression: if a future change ever emits an `ip6` accept
    /// path without a corresponding, deliberate security review, this test fails.
    /// See docs/firewall-model.md 第二節 for the full explanation.
    /// </summary>
    [Fact]
    public async Task GenerateAsync_NeverEmitsAnIpv6AcceptMatcher_Ipv6IsDeniedByConstruction()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = new Peer
        {
            PeerId = "peer-000000000001",
            Name = "test-peer",
            PublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            AssignedVpnIp = "10.250.0.10",
            Status = PeerStatus.Active,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        var resource = new ProtectedResource
        {
            ResourceId = "resource-000000000001",
            Name = "test-resource",
            Destination = "10.20.0.10",
            Protocol = Protocol.Tcp,
            Port = 443,
            Enabled = true,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        var policy = new AccessPolicy
        {
            RuleId = "rule-00000001",
            PeerId = peer.PeerId,
            ResourceId = resource.ResourceId,
            Enabled = true,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.Contains("table inet securetunnel", result.RenderedForReview);
        Assert.DoesNotContain("ip6 ", result.RenderedForReview, StringComparison.Ordinal);
        Assert.DoesNotContain("meta nfproto ipv6", result.RenderedForReview, StringComparison.Ordinal);
    }

    [Fact]
    public async Task GenerateAsync_DryRun_DoesNotWriteFile()
    {
        var config = TestConfigurationFactory.CreateValid();
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(),
            new FirewallGenerationOptions { DryRun = true, OutputPath = outputPath });

        Assert.True(result.Success);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_ExistingFileWithoutForce_RefusesToOverwrite()
    {
        var config = TestConfigurationFactory.CreateValid();
        var outputPath = TempPath();
        await File.WriteAllTextAsync(outputPath, "PRE-EXISTING");

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(),
            new FirewallGenerationOptions { OutputPath = outputPath, Force = false });

        Assert.False(result.Success);
        Assert.Equal("PRE-EXISTING", await File.ReadAllTextAsync(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_WritesFileWhenNotDryRun()
    {
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1", enabled: true);
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, new FirewallGenerationOptions { OutputPath = outputPath });

        Assert.True(result.Success);
        Assert.True(File.Exists(outputPath));
        Assert.Contains("10.250.0.10", await File.ReadAllTextAsync(outputPath));
    }

    private static Peer MakePeer(string id, PeerStatus status, string vpnIp) => new()
    {
        PeerId = id,
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = vpnIp,
        Status = status,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static ProtectedResource MakeResource(string id, string destination, int port, int? portEnd = null, bool enabled = true, Protocol protocol = Protocol.Tcp) => new()
    {
        ResourceId = id,
        Name = "test",
        Destination = destination,
        Protocol = protocol,
        Port = port,
        PortEnd = portEnd,
        Enabled = enabled,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static AccessPolicy MakePolicy(string ruleId, string peerId, string resourceId, bool enabled) => new()
    {
        RuleId = ruleId,
        PeerId = peerId,
        ResourceId = resourceId,
        Enabled = enabled,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-fwgen-{Guid.NewGuid():N}");
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
