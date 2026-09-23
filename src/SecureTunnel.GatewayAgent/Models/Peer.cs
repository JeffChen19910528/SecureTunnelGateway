namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// A registered VPN Client, identified by its WireGuard public key. The Gateway never
/// stores a Peer's private key - see docs/security-model.md 第一節 and
/// Peers/ClientConfigTemplateGenerator.cs. This type is serialized to the JSON peer
/// registry (Peers/JsonFilePeerRepository.cs); adding a field here means it will be
/// persisted to disk, so never add a secret field to this class.
/// </summary>
public sealed class Peer
{
    public required string PeerId { get; init; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>WireGuard public key (base64, 32 decoded bytes). Never a private key.</summary>
    public required string PublicKey { get; set; }

    public required string AssignedVpnIp { get; set; }

    public PeerStatus Status { get; set; } = PeerStatus.Active;

    public required DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset UpdatedAtUtc { get; set; }

    /// <summary>Last known handshake time, if the Gateway has observed one via `wg show`.</summary>
    public DateTimeOffset? LastHandshakeAtUtc { get; set; }

    /// <summary>Client-side endpoint last observed by WireGuard, if any (informational only).</summary>
    public string? Endpoint { get; set; }

    /// <summary>Networks this peer is allowed to originate traffic from, in the server's [Peer] block. Defaults to "&lt;AssignedVpnIp&gt;/32".</summary>
    public List<string> AllowedIps { get; set; } = new();

    public int? PersistentKeepaliveSeconds { get; set; }
}
