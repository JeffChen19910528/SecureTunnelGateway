using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class PolicyValidatorTests
{
    private readonly List<Peer> _peers;
    private readonly List<ProtectedResource> _resources;

    public PolicyValidatorTests()
    {
        _peers = new List<Peer>
        {
            MakePeer("peer-active", PeerStatus.Active),
            MakePeer("peer-disabled", PeerStatus.Disabled),
            MakePeer("peer-revoked", PeerStatus.Revoked),
            MakePeer("peer-removed", PeerStatus.Removed)
        };

        _resources = new List<ProtectedResource>
        {
            MakeResource("resource-enabled", enabled: true),
            MakeResource("resource-disabled", enabled: false)
        };
    }

    [Fact]
    public void Validate_ActivePeerEnabledResource_IsValidNoWarnings()
    {
        var policy = MakePolicy("peer-active", "resource-enabled");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.True(result.IsValid);
        Assert.Empty(result.Warnings);
    }

    [Fact]
    public void Validate_UnknownPeer_Rejected()
    {
        var policy = MakePolicy("peer-does-not-exist", "resource-enabled");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "peerId" && e.Message.Contains("Unknown"));
    }

    [Fact]
    public void Validate_UnknownResource_Rejected()
    {
        var policy = MakePolicy("peer-active", "resource-does-not-exist");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "resourceId" && e.Message.Contains("Unknown"));
    }

    [Theory]
    [InlineData("peer-disabled")]
    [InlineData("peer-revoked")]
    [InlineData("peer-removed")]
    public void Validate_NonActivePeer_IsValidButWarns(string peerId)
    {
        var policy = MakePolicy(peerId, "resource-enabled");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.True(result.IsValid, "a policy referencing a known-but-inactive peer is well-formed, not an error");
        Assert.Contains(result.Warnings, w => w.Field == "peerId");
    }

    [Fact]
    public void Validate_DisabledResource_IsValidButWarns()
    {
        var policy = MakePolicy("peer-active", "resource-disabled");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Field == "resourceId");
    }

    [Fact]
    public void Validate_EmptyPeerId_Rejected()
    {
        var policy = MakePolicy("", "resource-enabled");
        var result = new ValidationResult();

        PolicyValidator.Validate(policy, _peers, _resources, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "peerId" && e.Message.Contains("empty"));
    }

    private static AccessPolicy MakePolicy(string peerId, string resourceId) => new()
    {
        RuleId = "rule-test",
        PeerId = peerId,
        ResourceId = resourceId,
        Enabled = true,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static Peer MakePeer(string id, PeerStatus status) => new()
    {
        PeerId = id,
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = "10.250.0.10",
        Status = status,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static ProtectedResource MakeResource(string id, bool enabled) => new()
    {
        ResourceId = id,
        Name = "test",
        Destination = "10.20.0.10",
        Protocol = Protocol.Tcp,
        Port = 443,
        Enabled = enabled,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };
}
