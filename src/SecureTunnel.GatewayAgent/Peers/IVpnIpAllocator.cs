using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Allocates IPv4 addresses from the configured Client pool (network.clientAddressPoolStart
/// .. clientAddressPoolEnd). Pure/deterministic - takes the current peer set as an explicit
/// parameter rather than reading from storage itself, so it is unit-testable without any
/// file or process I/O.
/// </summary>
public interface IVpnIpAllocator
{
    /// <summary>
    /// Allocates an IP automatically, or validates and reserves <paramref name="requestedIp"/>
    /// when provided. <paramref name="excludePeerId"/> lets a peer's own current IP be
    /// treated as available when re-validating that same peer (e.g. on Enable).
    /// </summary>
    VpnIpAllocationResult Allocate(GatewayConfiguration config, IReadOnlyCollection<Peer> existingPeers, string? requestedIp = null, string? excludePeerId = null);

    bool IsAvailable(GatewayConfiguration config, IReadOnlyCollection<Peer> existingPeers, string ip, string? excludePeerId = null);
}
