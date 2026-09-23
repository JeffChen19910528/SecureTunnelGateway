namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// One resolved (Peer, Resource) authorization, after filtering to Active Peer + Enabled
/// Resource + Enabled Policy. This is the unit both the nftables renderer and the tests
/// operate on, so tests can assert on structured data instead of parsing rendered text.
/// </summary>
public sealed record EffectiveAccessRule(
    string RuleId,
    string PeerId,
    string PeerVpnIp,
    string ResourceId,
    string Destination,
    Protocol Protocol,
    int Port,
    int? PortEnd);

public sealed class FirewallGenerationOptions
{
    public bool DryRun { get; init; }
    public bool Force { get; init; }
    public string? OutputPath { get; init; }
}

public sealed class FirewallGenerationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public string? WrittenPath { get; init; }

    /// <summary>Full rendered nftables ruleset text - contains no secrets, always safe to display/log.</summary>
    public required string RenderedForReview { get; init; }

    public required IReadOnlyList<ValidationIssue> ValidationIssues { get; init; }
    public required IReadOnlyList<EffectiveAccessRule> EffectiveRules { get; init; }
}

/// <summary>
/// Apply lifecycle state - see docs/firewall-model.md "Apply 生命週期" and
/// Firewall/FirewallApplyOrchestrator.cs. Each state is only reached after the previous
/// one succeeds; a failure at any step reports the LAST state that succeeded, never a
/// state that was not actually reached.
/// </summary>
public enum FirewallApplyState
{
    NotStarted,
    Generated,
    SyntaxValidated,
    Applied,
    Verified,
    Failed
}

public sealed class FirewallApplyResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public required FirewallApplyState State { get; init; }
    public required string Message { get; init; }
    public IReadOnlyList<ValidationIssue> ValidationIssues { get; init; } = Array.Empty<ValidationIssue>();
}

public enum FirewallTableState
{
    Unknown,
    NotPresent,
    Present
}

public sealed class FirewallStatus
{
    public required FirewallTableState State { get; init; }
    public string? RawOutput { get; init; }
    public required string Message { get; init; }
}
