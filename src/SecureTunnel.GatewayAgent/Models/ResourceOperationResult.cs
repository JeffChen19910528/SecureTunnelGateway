namespace SecureTunnel.GatewayAgent.Models;

public sealed class ResourceOperationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public ProtectedResource? Resource { get; init; }
    public required string Message { get; init; }
    public PeerOperationFailureKind FailureKind { get; init; } = PeerOperationFailureKind.None;
    public IReadOnlyList<ValidationIssue> Issues { get; init; } = Array.Empty<ValidationIssue>();
}

public sealed class PolicyOperationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public AccessPolicy? Policy { get; init; }
    public required string Message { get; init; }
    public PeerOperationFailureKind FailureKind { get; init; } = PeerOperationFailureKind.None;
    public IReadOnlyList<ValidationIssue> Issues { get; init; } = Array.Empty<ValidationIssue>();
}
