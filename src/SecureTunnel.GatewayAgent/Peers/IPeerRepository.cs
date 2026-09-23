using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Thrown when the peer registry file exists but its content is invalid (malformed JSON,
/// missing required fields, duplicate PeerId/PublicKey). Loading fails closed - callers
/// must not silently treat this as "empty registry" or drop the offending records; see
/// docs/security-model.md "Persistence".
/// </summary>
public sealed class PeerRegistryCorruptException : Exception
{
    public PeerRegistryCorruptException(string message) : base(message) { }
}

public interface IPeerRepository
{
    /// <summary>
    /// Returns an empty list if <paramref name="storePath"/> does not exist yet (a fresh
    /// registry, not an error). <paramref name="storePath"/> is passed explicitly (rather
    /// than fixed at construction) so the repository stays a stateless, config-agnostic
    /// service - the caller decides which gateway.yaml's peerStorePath to use, matching
    /// how IConfigurationLoader/IWireGuardConfigGenerator already take config per call.
    /// </summary>
    Task<IReadOnlyList<Peer>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default);

    /// <summary>Atomically replaces the entire registry file's content.</summary>
    Task SaveAllAsync(string storePath, IReadOnlyList<Peer> peers, CancellationToken cancellationToken = default);
}
