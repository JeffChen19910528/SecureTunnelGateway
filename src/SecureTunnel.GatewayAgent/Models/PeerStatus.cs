namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Peer lifecycle state. See docs/security-model.md and docs/operations-guide.md for the
/// full semantics; summary:
///
/// - Pending: registered but not yet effective in WireGuard. Not produced by any CLI
///   command in Phase 3 (reserved for a future approval/Control Plane pre-registration
///   flow); included here so the state machine and persistence schema don't need to
///   change when that flow is added.
/// - Active: effective - appears in the generated WireGuard server configuration and
///   can connect.
/// - Disabled: temporarily excluded from effective configuration. Identity, VPN IP and
///   metadata are retained so it can be re-enabled later without re-registration.
/// - Revoked: security-driven, one-way invalidation. Excluded from effective
///   configuration; its VPN IP is released back to the pool, but its public key can
///   never be re-added as a new peer (see IPeerService - duplicate public key check
///   applies across ALL statuses, including Revoked and Removed).
/// - Removed: soft-deleted/archived. Excluded from effective configuration, VPN IP
///   released, but the record (and audit trail) is retained rather than hard-deleted -
///   see docs/security-model.md "Persistence" for the rationale.
/// </summary>
public enum PeerStatus
{
    Pending,
    Active,
    Disabled,
    Revoked,
    Removed
}
