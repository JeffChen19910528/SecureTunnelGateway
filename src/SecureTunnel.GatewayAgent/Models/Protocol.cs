namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Supported transport protocols for a Protected Resource. ICMP and "any" are
/// deliberately not offered in Phase 4 - see docs/firewall-model.md Known Limitations.
/// </summary>
public enum Protocol
{
    Tcp,
    Udp
}
