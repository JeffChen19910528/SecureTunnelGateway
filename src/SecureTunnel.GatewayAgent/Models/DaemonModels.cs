namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// The daemon's own startup/runtime classification (Phase 6A). Distinct from, and coarser
/// than, `gateway status`'s Healthy/Degraded/Blocked/Failed/Unknown - see
/// Daemon/GatewayDaemonService.cs for exactly which conditions map to which value and why.
/// Only <see cref="Failed"/> causes the process to exit; the other three keep the run loop
/// alive so the condition stays visible in journald/`gateway status` instead of crash-looping.
/// </summary>
public enum DaemonStartupStatus
{
    Healthy,
    Degraded,
    Blocked,
    Failed
}

/// <summary>Outcome of one startup or periodic-tick evaluation pass.</summary>
public sealed class DaemonStartupResult
{
    public required DaemonStartupStatus Status { get; init; }
    public required string Message { get; init; }

    /// <summary>Non-null when Phase 5 crash-recovery detected an interrupted operation.</summary>
    public string? IncompleteOperation { get; init; }
}

/// <summary>Options for a single `gateway serve` invocation.</summary>
public sealed class DaemonRunOptions
{
    public TimeSpan HealthCheckInterval { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>Run startup validation and a single state check, then exit - never enters the persistent loop.</summary>
    public bool RunOnce { get; init; }
}
