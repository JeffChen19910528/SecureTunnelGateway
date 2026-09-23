using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Lifecycle;

/// <summary>
/// Orchestrates the full Desired -> Candidate -> Validated -> Applied -> Verified -> Active
/// lifecycle across BOTH data-plane components (WireGuard and nftables) as a single
/// operation, and rollback to a previously-verified version. See docs/architecture.md
/// "Configuration Lifecycle" for the full state diagram and docs/security-model.md for the
/// partial-failure handling rationale (WireGuard succeeds/nftables fails and vice versa).
/// </summary>
public interface IConfigurationLifecycleService
{
    Task<ConfigurationHistory> GetHistoryAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    Task<ConfigurationSnapshot?> GetVersionAsync(GatewayConfiguration config, int version, CancellationToken cancellationToken = default);

    /// <summary>
    /// Captures the live Peer/Resource/Policy Registries as a new candidate, validates it,
    /// and (unless dryRun) applies + verifies it end to end, updating Active/LastKnownGood
    /// only on full success.
    /// </summary>
    Task<ConfigurationApplyResult> ApplyAsync(GatewayConfiguration config, string sourceReason, bool dryRun, CancellationToken cancellationToken = default);

    /// <summary>
    /// Re-applies a previously recorded version's IMMUTABLE snapshot data (never the live,
    /// possibly-since-changed Registries) as a new version. Only versions that previously
    /// reached Verified/Active/RollbackSucceeded are valid rollback targets.
    /// </summary>
    Task<ConfigurationApplyResult> RollbackAsync(GatewayConfiguration config, int targetVersion, bool dryRun, CancellationToken cancellationToken = default);

    /// <summary>Checks the actual current effective state (WireGuard interface + nftables table), independent of what history says.</summary>
    Task<ConfigurationVerifyResult> VerifyAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    /// <summary>
    /// Compares the live Peer/Resource/Policy Registries' content hash against the Active
    /// version's recorded hash (see Lifecycle/SnapshotHasher). True means the Registries
    /// have changed since the last successful `config apply` - i.e. Desired has drifted
    /// from Active and a fresh `config apply` is needed to pick up the change. See
    /// docs/security-model.md "Registry Consistency" (Phase 6).
    /// </summary>
    Task<bool> IsDesiredStaleAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    /// <summary>
    /// Startup/health-check recovery probe: inspects history for a version left in a
    /// non-terminal state (Applying/ApplyPending/RollbackPending), which indicates the
    /// process was interrupted mid-operation. Never returns a false "all clear" - see
    /// docs/security-model.md "Crash Recovery".
    /// </summary>
    Task<string?> DetectIncompleteOperationAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);
}
