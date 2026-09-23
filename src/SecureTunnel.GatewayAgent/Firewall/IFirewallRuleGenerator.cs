using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Renders the SecureTunnel nftables ruleset (table "inet securetunnel") from the current
/// Peer/Resource/Policy state. See docs/firewall-model.md for the full table/chain design
/// and the NAT packet-flow rationale. Deterministic: the same input always produces
/// byte-identical output (rules are sorted, never emitted in registry/dictionary order).
/// </summary>
public interface IFirewallRuleGenerator
{
    Task<FirewallGenerationResult> GenerateAsync(
        GatewayConfiguration configuration,
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        FirewallGenerationOptions options,
        CancellationToken cancellationToken = default);
}
