namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Result of a single point-in-time check (environment validation, health check item, etc).
/// Mirrors the PASS/WARN/FAIL/BLOCKED vocabulary used by scripts/validate-environment.sh.
/// </summary>
public enum CheckStatus
{
    Pass,
    Warn,
    Fail,
    Blocked
}
