using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Orchestrates Peer lifecycle operations (validation + IP allocation + persistence).
/// Every mutating method accepts <c>dryRun</c>: when true, the method performs the same
/// validation and computes the same result it would otherwise persist, but never calls
/// IPeerRepository.SaveAllAsync - see docs/operations-guide.md "Dry-run".
/// </summary>
public interface IPeerService
{
    Task<IReadOnlyList<Peer>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    Task<Peer?> GetAsync(GatewayConfiguration config, string peerId, CancellationToken cancellationToken = default);

    /// <summary>Peers eligible to appear in the effective WireGuard server configuration (Status == Active only).</summary>
    Task<IReadOnlyList<Peer>> GetEffectivePeersAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    Task<PeerOperationResult> AddAsync(GatewayConfiguration config, string name, string publicKey, string? description, string? requestedVpnIp, bool dryRun, CancellationToken cancellationToken = default);

    Task<PeerOperationResult> EnableAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default);

    Task<PeerOperationResult> DisableAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default);

    Task<PeerOperationResult> RevokeAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default);

    Task<PeerOperationResult> RemoveAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default);
}
