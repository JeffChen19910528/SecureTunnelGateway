using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Health;

/// <summary>
/// Aggregates read-only checks (environment, configuration validity, key permissions,
/// active configuration presence) into an overall Healthy/Degraded/Unhealthy/Unknown
/// status. Never modifies system state - see docs/operations-guide.md.
/// </summary>
public interface IHealthCheckService
{
    Task<HealthCheckReport> CheckAsync(string? configPath, CancellationToken cancellationToken = default);
}
