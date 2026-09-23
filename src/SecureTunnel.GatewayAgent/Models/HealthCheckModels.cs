namespace SecureTunnel.GatewayAgent.Models;

public sealed record HealthCheckItem(string Id, CheckStatus Status, string Message);

public sealed class HealthCheckReport
{
    public required HealthStatus OverallStatus { get; init; }
    public required IReadOnlyList<HealthCheckItem> Items { get; init; }
    public required DateTimeOffset CheckedAtUtc { get; init; }
}

/// <summary>Result of parsing scripts/validate-environment.sh --json output.</summary>
public sealed record EnvironmentCheckResult(string Id, CheckStatus Status, string Message);
