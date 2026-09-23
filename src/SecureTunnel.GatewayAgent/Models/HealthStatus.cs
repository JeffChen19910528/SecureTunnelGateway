namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Overall Gateway health status, as required by docs/architecture.md and docs/operations-guide.md.
/// </summary>
public enum HealthStatus
{
    Unknown,
    Healthy,
    Degraded,
    Unhealthy
}
