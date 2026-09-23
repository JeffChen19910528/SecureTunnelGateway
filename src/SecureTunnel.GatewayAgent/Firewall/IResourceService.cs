using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Protected Resource lifecycle. Unlike Peers (see Peers/IPeerService.cs), Resources carry
/// no identity-reuse risk, so `Remove` is a genuine (hard) delete rather than a soft-delete/
/// archive - there is no equivalent of "a revoked key must never be silently reusable" here.
/// </summary>
public interface IResourceService
{
    Task<IReadOnlyList<ProtectedResource>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);
    Task<ProtectedResource?> GetAsync(GatewayConfiguration config, string resourceId, CancellationToken cancellationToken = default);

    Task<ResourceOperationResult> AddAsync(GatewayConfiguration config, string name, string destination, Protocol protocol, int port, int? portEnd, string? description, bool dryRun, CancellationToken cancellationToken = default);
    Task<ResourceOperationResult> EnableAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default);
    Task<ResourceOperationResult> DisableAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default);
    Task<ResourceOperationResult> RemoveAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default);
}
