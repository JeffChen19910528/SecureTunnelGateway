namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Lifecycle state of a single configuration version (see Lifecycle/ConfigurationLifecycleService.cs
/// and docs/architecture.md "Configuration Lifecycle"). Every state transition is recorded -
/// this is never collapsed into a single "isApplied" boolean, so a version's history is
/// always fully reconstructable from the Configuration History file.
/// </summary>
public enum ConfigurationState
{
    /// <summary>Desired state computed from the live Registries, not yet turned into a candidate.</summary>
    Desired,

    /// <summary>An immutable snapshot (Peer/Resource/Policy lists + content hash) has been captured.</summary>
    CandidateGenerated,

    /// <summary>The candidate passed GatewayConfigurationValidator + Firewall/PolicyValidator checks.</summary>
    Validated,

    /// <summary>Validated and persisted to history; about to start touching the system.</summary>
    ApplyPending,

    /// <summary>Actively writing WireGuard/nftables state - if the process dies here, recovery must detect this.</summary>
    Applying,

    /// <summary>All apply steps (WireGuard + nftables) reported success; not yet verified.</summary>
    Applied,

    /// <summary>Post-apply verification (interface up, table present) confirmed the change took effect.</summary>
    Verified,

    /// <summary>The single version currently considered "live" - always the last Verified version.</summary>
    Active,

    // --- Failure / recovery states ---

    ValidationFailed,
    ApplyFailed,
    VerificationFailed,
    RollbackPending,
    RollbackSucceeded,
    RollbackFailed,

    /// <summary>
    /// A partial failure (e.g. WireGuard applied but nftables did not, or the process was
    /// interrupted mid-apply) left the actual effective state impossible to determine with
    /// confidence. Never silently treated as Active or as a clean failure - see
    /// docs/security-model.md "Effective State Unknown".
    /// </summary>
    EffectiveStateUnknown
}
