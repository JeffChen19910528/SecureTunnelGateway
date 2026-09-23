namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// An explicit grant of one Peer's access to one Protected Resource. There is no "Deny"
/// action and no priority ordering - Phase 4 deliberately uses an allow-only model with
/// implicit deny (see docs/firewall-model.md 第三節): the absence of a matching enabled
/// AccessPolicy for an Active Peer + Enabled Resource pair already means "denied", so a
/// separate Deny rule type would only add complexity (precedence rules) without adding
/// any capability the MVP needs.
/// </summary>
public sealed class AccessPolicy
{
    public required string RuleId { get; init; }
    public required string PeerId { get; set; }
    public required string ResourceId { get; set; }
    public bool Enabled { get; set; } = true;
    public string? Description { get; set; }

    public required DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
