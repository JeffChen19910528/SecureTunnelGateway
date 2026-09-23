using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Implements the "firewall apply" lifecycle from docs/firewall-model.md: validate ->
/// generate candidate -> syntax-check candidate -> (only then) replace the active ruleset,
/// backing up the previous one first -> apply -> verify -> report success only if
/// verification confirms the table is actually present. A failure at any step leaves the
/// previously-applied ruleset (if any) untouched and is reported as Failed, never as a
/// partial success - see docs/security-model.md "Firewall Fail-Closed".
///
/// Full candidate/active versioning with rollback-to-any-version is Phase 5 scope; this
/// orchestrator only guarantees the single most recent known-good state is recoverable
/// (via the `.lastknowngood` backup file next to the active ruleset).
/// </summary>
public interface IFirewallApplyOrchestrator
{
    Task<FirewallApplyResult> ApplyAsync(
        GatewayConfiguration configuration,
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        bool dryRun,
        CancellationToken cancellationToken = default);
}
