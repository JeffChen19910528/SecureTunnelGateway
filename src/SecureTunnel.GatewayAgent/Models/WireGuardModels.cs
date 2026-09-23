namespace SecureTunnel.GatewayAgent.Models;

public sealed record WireGuardKeyPair(SensitiveString PrivateKey, string PublicKey);

public sealed class KeyGenerationOptions
{
    public bool DryRun { get; init; }
    public bool Force { get; init; }
}

public sealed class KeyGenerationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public string? PublicKey { get; init; }
    public string? PrivateKeyPath { get; init; }
    public string? PublicKeyPath { get; init; }
    public required string Message { get; init; }
}

public sealed class KeyPermissionCheckResult
{
    public required bool Exists { get; init; }
    public required bool PermissionsOk { get; init; }
    public string? Message { get; init; }
}

public sealed class ConfigGenerationOptions
{
    public bool DryRun { get; init; }
    public bool Force { get; init; }
    public string? OutputPath { get; init; }
}

public sealed class ConfigGenerationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public string? WrittenPath { get; init; }

    /// <summary>Full rendered configuration text for human review; PrivateKey is always redacted here.</summary>
    public required string RenderedForReview { get; init; }

    public required IReadOnlyList<ValidationIssue> ValidationIssues { get; init; }
}

public enum WireGuardInterfaceState
{
    Unknown,
    NotConfigured,
    Down,
    Up
}

public sealed class WireGuardStatus
{
    public required WireGuardInterfaceState State { get; init; }
    public string? RawOutput { get; init; }
    public required string Message { get; init; }
}
