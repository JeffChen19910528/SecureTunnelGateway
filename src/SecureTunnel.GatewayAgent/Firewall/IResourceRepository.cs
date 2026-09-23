using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>Thrown when the resource registry file exists but is invalid. See Peers/PeerRegistryCorruptException for the same fail-closed rationale.</summary>
public sealed class ResourceRegistryCorruptException : Exception
{
    public ResourceRegistryCorruptException(string message) : base(message) { }
}

public interface IResourceRepository
{
    Task<IReadOnlyList<ProtectedResource>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default);
    Task SaveAllAsync(string storePath, IReadOnlyList<ProtectedResource> resources, CancellationToken cancellationToken = default);
}
