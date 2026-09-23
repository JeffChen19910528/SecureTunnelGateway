using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;
using Xunit;

namespace SecureTunnel.GatewayAgent.LifecycleTests;

public sealed class SnapshotHasherTests
{
    [Fact]
    public void ComputeHash_SameContentDifferentOrder_ProducesSameHash()
    {
        var peerA = MakePeer("peer-a");
        var peerB = MakePeer("peer-b");

        var hash1 = SnapshotHasher.ComputeHash(new[] { peerA, peerB }, Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>());
        var hash2 = SnapshotHasher.ComputeHash(new[] { peerB, peerA }, Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>());

        Assert.Equal(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_DifferentContent_ProducesDifferentHash()
    {
        var peerA = MakePeer("peer-a");
        var peerAModified = MakePeer("peer-a");
        peerAModified.Status = PeerStatus.Disabled;

        var hash1 = SnapshotHasher.ComputeHash(new[] { peerA }, Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>());
        var hash2 = SnapshotHasher.ComputeHash(new[] { peerAModified }, Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>());

        Assert.NotEqual(hash1, hash2);
    }

    [Fact]
    public void ComputeHash_NeverContainsPrivateKeyMaterial()
    {
        // Structural guarantee check: Peer has no private-key field, so nothing to leak,
        // but assert the hash output itself is a plain hex digest with no embedded content.
        var hash = SnapshotHasher.ComputeHash(new[] { MakePeer("peer-a") }, Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>());

        Assert.Matches("^[0-9a-f]{64}$", hash);
    }

    private static Peer MakePeer(string id) => new()
    {
        PeerId = id,
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = "10.250.0.10",
        Status = PeerStatus.Active,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };
}
