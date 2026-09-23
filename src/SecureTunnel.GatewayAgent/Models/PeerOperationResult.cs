namespace SecureTunnel.GatewayAgent.Models;

/// <summary>Outcome category, so callers (CLI) can distinguish these without string matching.</summary>
public enum PeerOperationFailureKind
{
    None,
    ValidationFailed,
    PersistenceFailed,
    NotFound,
    Conflict
}

public sealed class PeerOperationResult
{
    public required bool Success { get; init; }
    public required bool DryRun { get; init; }
    public Peer? Peer { get; init; }
    public required string Message { get; init; }
    public PeerOperationFailureKind FailureKind { get; init; } = PeerOperationFailureKind.None;
    public IReadOnlyList<ValidationIssue> Issues { get; init; } = Array.Empty<ValidationIssue>();
}
