namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// An immutable record of one configuration version: the exact Peer/Resource/Policy data
/// used to generate it, what happened when it was (or wasn't) applied, and why. Never
/// mutated in place after creation - a rollback or retry always creates a NEW version that
/// references this one, rather than rewriting history (see Lifecycle/ConfigurationLifecycleService).
///
/// Deliberately does NOT contain the rendered WireGuard [Interface] text (which would
/// require embedding the server private key to be useful) or any secret material - only
/// the non-secret Peer/Resource/Policy snapshot needed to REGENERATE the WireGuard and
/// nftables configuration deterministically from data that is already known to be
/// secret-free (see docs/security-model.md "Snapshot Design").
/// </summary>
public sealed class ConfigurationSnapshot
{
    /// <summary>Monotonically increasing, unique within a given ConfigurationHistory.</summary>
    public required int Version { get; init; }

    public required DateTimeOffset CreatedAtUtc { get; init; }

    /// <summary>Human-readable reason this version was generated, e.g. "peer add: Alice Laptop", "manual apply", "rollback to v4".</summary>
    public required string SourceReason { get; init; }

    /// <summary>SHA-256 hex digest over the canonical (sorted, secret-free) serialization of the snapshot content - see Lifecycle/SnapshotHasher.</summary>
    public required string ContentHash { get; init; }

    public ConfigurationState State { get; set; }

    /// <summary>Immutable copies of the Peer/Resource/Policy data at the moment this candidate was generated.</summary>
    public required IReadOnlyList<Peer> Peers { get; init; }
    public required IReadOnlyList<ProtectedResource> Resources { get; init; }
    public required IReadOnlyList<AccessPolicy> Policies { get; init; }

    /// <summary>Number of [Peer] blocks this version's WireGuard config would contain (Active peers only).</summary>
    public required int EffectiveWireGuardPeerCount { get; init; }

    /// <summary>Number of effective nftables allow rules this version's ruleset would contain.</summary>
    public required int EffectiveFirewallRuleCount { get; init; }

    public string? FailureReason { get; set; }

    /// <summary>True once WireGuard config was successfully written + interface (re)started.</summary>
    public bool WireGuardApplied { get; set; }

    /// <summary>True once the nftables ruleset was successfully applied and verified present.</summary>
    public bool FirewallApplied { get; set; }

    /// <summary>If this version is the result of a rollback, the version it targeted.</summary>
    public int? RollbackTargetVersion { get; set; }

    /// <summary>If this version replaced a previously Active version, that version's number (becomes Last Known Good on success).</summary>
    public int? PreviousActiveVersion { get; set; }
}
