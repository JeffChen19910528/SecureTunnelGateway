namespace SecureTunnel.GatewayAgent.Models;

public sealed class ConfigurationApplyResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public required ConfigurationState State { get; init; }
    public int? Version { get; init; }
    public required string Message { get; init; }
    public IReadOnlyList<ValidationIssue> ValidationIssues { get; init; } = Array.Empty<ValidationIssue>();
}

public sealed class ConfigurationVerifyResult
{
    public required bool WireGuardUp { get; init; }
    public required bool FirewallTablePresent { get; init; }
    public required bool EffectiveStateKnown { get; init; }
    public required string Message { get; init; }
}

/// <summary>Result of attempting to acquire the single-writer operation lock (see Lifecycle/IOperationLock.cs).</summary>
public sealed class LockAcquisitionResult
{
    public required bool Acquired { get; init; }
    public string? Message { get; init; }
}
