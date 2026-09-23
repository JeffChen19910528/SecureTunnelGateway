using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.PeerTests;

public sealed class Ipv4VpnIpAllocatorTests
{
    private readonly Ipv4VpnIpAllocator _allocator = new();

    [Fact]
    public void Allocate_EmptyPool_ReturnsFirstAddress()
    {
        var config = TestConfigurationFactory.CreateValid(); // pool 10.250.0.10 - 10.250.0.200

        var result = _allocator.Allocate(config, Array.Empty<Peer>());

        Assert.True(result.Success);
        Assert.Equal("10.250.0.10", result.AllocatedIp);
    }

    [Fact]
    public void Allocate_SomeOccupied_ReturnsNextFree()
    {
        var config = TestConfigurationFactory.CreateValid();
        var existing = new[] { MakePeer("10.250.0.10", PeerStatus.Active), MakePeer("10.250.0.11", PeerStatus.Active) };

        var result = _allocator.Allocate(config, existing);

        Assert.True(result.Success);
        Assert.Equal("10.250.0.12", result.AllocatedIp);
    }

    [Fact]
    public void Allocate_ExplicitAvailableIp_IsReserved()
    {
        var config = TestConfigurationFactory.CreateValid();

        var result = _allocator.Allocate(config, Array.Empty<Peer>(), requestedIp: "10.250.0.50");

        Assert.True(result.Success);
        Assert.Equal("10.250.0.50", result.AllocatedIp);
    }

    [Fact]
    public void Allocate_ExplicitDuplicateIp_Rejected()
    {
        var config = TestConfigurationFactory.CreateValid();
        var existing = new[] { MakePeer("10.250.0.50", PeerStatus.Active) };

        var result = _allocator.Allocate(config, existing, requestedIp: "10.250.0.50");

        Assert.False(result.Success);
        Assert.Contains("already assigned", result.Message);
    }

    [Fact]
    public void Allocate_ExplicitGatewayIp_RejectedWhenInsidePool()
    {
        var config = TestConfigurationFactory.CreateValid(); // gateway = 10.250.0.1
        config.Network.ClientAddressPoolStart = "10.250.0.1"; // widen pool to include the gateway address
        config.Network.ClientAddressPoolEnd = "10.250.0.5";

        var result = _allocator.Allocate(config, Array.Empty<Peer>(), requestedIp: "10.250.0.1");

        Assert.False(result.Success);
        Assert.Contains("Gateway", result.Message);
    }

    [Fact]
    public void Allocate_AutomaticAllocation_SkipsGatewayIpWhenInsidePool()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolStart = "10.250.0.1"; // includes the gateway address at the start
        config.Network.ClientAddressPoolEnd = "10.250.0.5";

        var result = _allocator.Allocate(config, Array.Empty<Peer>());

        Assert.True(result.Success);
        Assert.NotEqual("10.250.0.1", result.AllocatedIp);
    }

    [Fact]
    public void Allocate_ExplicitNetworkAddress_RejectedWhenInsidePool()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolStart = "10.250.0.0"; // widen pool to include network address
        config.Network.ClientAddressPoolEnd = "10.250.0.5";

        var result = _allocator.Allocate(config, Array.Empty<Peer>(), requestedIp: "10.250.0.0");

        Assert.False(result.Success);
        Assert.Contains("network address", result.Message);
    }

    [Fact]
    public void Allocate_ExplicitBroadcastAddress_RejectedWhenInsidePool()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolStart = "10.250.0.250";
        config.Network.ClientAddressPoolEnd = "10.250.0.255"; // includes .255 broadcast for /24

        var result = _allocator.Allocate(config, Array.Empty<Peer>(), requestedIp: "10.250.0.255");

        Assert.False(result.Success);
        Assert.Contains("broadcast address", result.Message);
    }

    [Fact]
    public void Allocate_ExplicitIpOutsidePool_Rejected()
    {
        var config = TestConfigurationFactory.CreateValid();

        var result = _allocator.Allocate(config, Array.Empty<Peer>(), requestedIp: "10.250.0.201");

        Assert.False(result.Success);
        Assert.Contains("outside the configured client pool", result.Message);
    }

    [Fact]
    public void Allocate_PoolExhausted_ReturnsFailureNotThrow()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolStart = "10.250.0.10";
        config.Network.ClientAddressPoolEnd = "10.250.0.11"; // only 2 addresses

        var existing = new[] { MakePeer("10.250.0.10", PeerStatus.Active), MakePeer("10.250.0.11", PeerStatus.Disabled) };

        var result = _allocator.Allocate(config, existing);

        Assert.False(result.Success);
        Assert.Contains("exhausted", result.Message);
    }

    [Theory]
    [InlineData(PeerStatus.Pending)]
    [InlineData(PeerStatus.Active)]
    [InlineData(PeerStatus.Disabled)]
    public void Allocate_OccupyingStatuses_BlockReuseOfSameIp(PeerStatus status)
    {
        var config = TestConfigurationFactory.CreateValid();
        var existing = new[] { MakePeer("10.250.0.10", status) };

        var result = _allocator.Allocate(config, existing, requestedIp: "10.250.0.10");

        Assert.False(result.Success);
    }

    [Theory]
    [InlineData(PeerStatus.Revoked)]
    [InlineData(PeerStatus.Removed)]
    public void Allocate_ReleasedStatuses_AllowReuseOfSameIp(PeerStatus status)
    {
        var config = TestConfigurationFactory.CreateValid();
        var existing = new[] { MakePeer("10.250.0.10", status) };

        var result = _allocator.Allocate(config, existing, requestedIp: "10.250.0.10");

        Assert.True(result.Success);
        Assert.Equal("10.250.0.10", result.AllocatedIp);
    }

    [Fact]
    public void IsAvailable_ExcludePeerId_TreatsOwnIpAsAvailable()
    {
        var config = TestConfigurationFactory.CreateValid();
        var self = MakePeer("10.250.0.10", PeerStatus.Disabled, peerId: "peer-self");

        var available = _allocator.IsAvailable(config, new[] { self }, "10.250.0.10", excludePeerId: "peer-self");

        Assert.True(available);
    }

    [Fact]
    public void IsAvailable_WithoutExclude_OwnIpIsNotAvailable()
    {
        var config = TestConfigurationFactory.CreateValid();
        var self = MakePeer("10.250.0.10", PeerStatus.Disabled, peerId: "peer-self");

        var available = _allocator.IsAvailable(config, new[] { self }, "10.250.0.10");

        Assert.False(available);
    }

    private static Peer MakePeer(string ip, PeerStatus status, string? peerId = null) => new()
    {
        PeerId = peerId ?? $"peer-{Guid.NewGuid():N}"[..12],
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = ip,
        Status = status,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };
}
