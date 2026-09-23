namespace SecureTunnel.GatewayAgent.Daemon;

/// <summary>
/// Abstraction over "wait until the next periodic check is due", so GatewayDaemonService's
/// run loop can be unit-tested deterministically (fake ticker, N ticks then cancel) instead
/// of depending on real wall-clock time.
/// </summary>
public interface IDaemonTicker
{
    /// <summary>
    /// Waits for the next tick. Throws <see cref="OperationCanceledException"/> if
    /// <paramref name="cancellationToken"/> is cancelled before the interval elapses -
    /// callers treat that as "stop the loop", never as an error.
    /// </summary>
    Task WaitForNextTickAsync(TimeSpan interval, CancellationToken cancellationToken);
}
