using System.Collections.Concurrent;
using SecureTunnel.GatewayAgent.Daemon;

namespace SecureTunnel.GatewayAgent.DaemonTests;

/// <summary>
/// Deterministic <see cref="IDaemonTicker"/> test double: completes immediately for the
/// first <see cref="TicksBeforeCancel"/> calls, then throws <see cref="OperationCanceledException"/>
/// (simulating the interval elapsing after a shutdown signal), so daemon loop tests run in
/// milliseconds instead of depending on real wall-clock waits.
/// </summary>
public sealed class FakeDaemonTicker : IDaemonTicker
{
    private int _calls;

    public int TicksBeforeCancel { get; set; } = 1;
    public ConcurrentQueue<TimeSpan> ObservedIntervals { get; } = new();

    public Task WaitForNextTickAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        ObservedIntervals.Enqueue(interval);
        var call = Interlocked.Increment(ref _calls);
        if (call > TicksBeforeCancel)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        return Task.CompletedTask;
    }

    public int CallCount => _calls;
}
