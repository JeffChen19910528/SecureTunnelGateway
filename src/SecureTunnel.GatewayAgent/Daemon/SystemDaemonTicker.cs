namespace SecureTunnel.GatewayAgent.Daemon;

/// <summary>Real, wall-clock-based <see cref="IDaemonTicker"/> used in production (via <see cref="PeriodicTimer"/> - never a busy loop).</summary>
public sealed class SystemDaemonTicker : IDaemonTicker
{
    public async Task WaitForNextTickAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(interval);
        await timer.WaitForNextTickAsync(cancellationToken);
    }
}
