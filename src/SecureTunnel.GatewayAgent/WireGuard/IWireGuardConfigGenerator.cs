using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.WireGuard;

/// <summary>
/// Produces a wg-quick compatible [Interface] configuration from a
/// <see cref="GatewayConfiguration"/>. Peer ([Peer]) sections are added later by Phase 3's
/// Peer management; this phase only bootstraps the interface itself.
/// </summary>
public interface IWireGuardConfigGenerator
{
    /// <summary>
    /// Validates <paramref name="configuration"/>, renders the WireGuard config (interface
    /// section plus one [Peer] block per entry in <paramref name="effectivePeers"/>), and
    /// (unless <see cref="ConfigGenerationOptions.DryRun"/> is set) writes it to disk with
    /// owner-only permissions. The private key is read from disk just before writing and
    /// is never included in the returned <see cref="ConfigGenerationResult.RenderedForReview"/>.
    /// Callers are expected to pass only Peers eligible for the effective configuration
    /// (Status == Active - see Peers/IPeerService.GetEffectivePeersAsync); this method
    /// additionally re-checks for duplicate public keys/AllowedIPs within the given list
    /// as a defense-in-depth safety net, not as the primary enforcement point.
    /// </summary>
    Task<ConfigGenerationResult> GenerateAsync(GatewayConfiguration configuration, IReadOnlyList<Peer> effectivePeers, ConfigGenerationOptions options, CancellationToken cancellationToken = default);
}
