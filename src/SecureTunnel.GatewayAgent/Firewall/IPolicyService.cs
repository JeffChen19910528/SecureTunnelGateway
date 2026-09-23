using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

public interface IPolicyService
{
    Task<IReadOnlyList<AccessPolicy>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);
    Task<AccessPolicy?> GetAsync(GatewayConfiguration config, string ruleId, CancellationToken cancellationToken = default);

    Task<PolicyOperationResult> AddAsync(GatewayConfiguration config, string peerId, string resourceId, string? description, bool dryRun, CancellationToken cancellationToken = default);
    Task<PolicyOperationResult> EnableAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default);
    Task<PolicyOperationResult> DisableAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default);
    Task<PolicyOperationResult> RemoveAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default);
}
