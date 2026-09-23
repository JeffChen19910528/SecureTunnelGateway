namespace SecureTunnel.GatewayAgent.Models;

public sealed class RoutingConfiguration
{
    /// <summary>
    /// Only "nat" is supported in this release (see docs/network-topology.md,
    /// NAT Mode 採用理由與限制). "routed" is accepted as a recognizable value so
    /// validation can reject it with a clear "not yet supported" message instead
    /// of an opaque parse error.
    /// </summary>
    public string Mode { get; set; } = "nat";

    public bool EnableIpv4Forwarding { get; set; } = true;

    /// <summary>Not enabled by default; see docs/security-model.md 第十五節 IPv6 洩漏.</summary>
    public bool EnableIpv6Forwarding { get; set; } = false;

    /// <summary>
    /// Explicit acknowledgement required before EnableIpv6Forwarding may be true.
    /// This exists so IPv6 forwarding can never be turned on "by accident" alongside
    /// an unrelated IPv4 change.
    /// </summary>
    public bool Ipv6PolicyAcknowledged { get; set; } = false;

    public bool NatEnabled { get; set; } = true;
}
