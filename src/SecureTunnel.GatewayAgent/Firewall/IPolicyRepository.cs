using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class PolicyRegistryCorruptException : Exception
{
    public PolicyRegistryCorruptException(string message) : base(message) { }
}

public interface IPolicyRepository
{
    Task<IReadOnlyList<AccessPolicy>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default);
    Task SaveAllAsync(string storePath, IReadOnlyList<AccessPolicy> policies, CancellationToken cancellationToken = default);
}
