using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Validates a single AccessPolicy against the known Peer and Resource sets.
///
/// Design choice (documented in docs/firewall-model.md 第三節): referencing a Peer/Resource
/// that does not exist at all is a hard ERROR (the policy is meaningless - "Unknown Peer
/// must be denied" from docs/security-model.md). Referencing a Peer that currently is
/// Disabled/Revoked/Removed, or a Resource that is currently disabled, is only a WARNING:
/// the policy is well-formed and will simply produce no effective rule right now (see
/// Firewall/FirewallRuleGenerator's Active/Enabled filtering) - this lets an operator
/// pre-define or keep a policy across a temporary Peer disable without having to delete
/// and recreate it every time.
/// </summary>
public static class PolicyValidator
{
    public static void Validate(AccessPolicy policy, IReadOnlyList<Peer> peers, IReadOnlyList<ProtectedResource> resources, ValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(policy.PeerId))
        {
            result.AddError("peerId", "peerId must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(policy.ResourceId))
        {
            result.AddError("resourceId", "resourceId must not be empty.");
        }

        var peer = peers.FirstOrDefault(p => string.Equals(p.PeerId, policy.PeerId, StringComparison.Ordinal));
        if (peer is null)
        {
            if (!string.IsNullOrWhiteSpace(policy.PeerId))
            {
                result.AddError("peerId", $"Unknown peer '{policy.PeerId}'. A policy must reference a peer that exists in the Peer Registry.");
            }
        }
        else if (peer.Status != PeerStatus.Active)
        {
            result.AddWarning("peerId", $"Peer '{policy.PeerId}' is currently {peer.Status}; this policy will produce no effective access until the peer is Active.");
        }

        var resource = resources.FirstOrDefault(r => string.Equals(r.ResourceId, policy.ResourceId, StringComparison.Ordinal));
        if (resource is null)
        {
            if (!string.IsNullOrWhiteSpace(policy.ResourceId))
            {
                result.AddError("resourceId", $"Unknown resource '{policy.ResourceId}'. A policy must reference a resource that exists in the Resource Registry.");
            }
        }
        else if (!resource.Enabled)
        {
            result.AddWarning("resourceId", $"Resource '{policy.ResourceId}' is currently disabled; this policy will produce no effective access until the resource is re-enabled.");
        }
    }
}
