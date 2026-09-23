using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Daemon;

/// <summary>
/// Runs the Gateway Agent as a persistent, systemd-managed process (Phase 6A). See
/// GatewayDaemonService.cs for the full startup-classification rationale and
/// docs/operations-guide.md "Gateway Daemon" for the operator-facing explanation.
/// </summary>
public interface IGatewayDaemonService
{
    /// <summary>
    /// Loads and validates configuration, runs startup diagnostics, then either exits
    /// (RunOnce, or a fatal/Failed startup) or enters the persistent run loop until
    /// <paramref name="cancellationToken"/> is cancelled (SIGINT/SIGTERM). Returns the
    /// process exit code - never throws for an ordinary startup/runtime problem (those are
    /// reported via the return code and logs), only for something the caller cannot recover
    /// from (e.g. a bug).
    /// </summary>
    Task<int> RunAsync(string configPath, DaemonRunOptions options, CancellationToken cancellationToken);
}
