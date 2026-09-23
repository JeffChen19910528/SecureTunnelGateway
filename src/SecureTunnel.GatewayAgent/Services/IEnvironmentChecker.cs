using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Runs the read-only environment validation logic (scripts/validate-environment.sh)
/// and returns structured results so CLI/health commands can reuse the exact same
/// checks instead of re-implementing detection logic in C#.
/// </summary>
public interface IEnvironmentChecker
{
    Task<IReadOnlyList<EnvironmentCheckResult>> RunChecksAsync(CancellationToken cancellationToken = default);
}
