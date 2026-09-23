using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.DaemonTests;

/// <summary>
/// Test double for <see cref="IHealthCheckService"/> used only to prove GatewayDaemonService's
/// outer "unexpected exception during startup diagnostics" path (RunAsync's Failed branch)
/// actually works - the real HealthCheckService catches everything internally and never
/// throws, so exercising that branch needs an injected double that does.
/// </summary>
public sealed class FakeHealthCheckService : IHealthCheckService
{
    private int _calls;

    /// <summary>1-based call number on which to throw; 0 = always return <see cref="Report"/>.</summary>
    public int ThrowOnCall { get; set; }

    public HealthCheckReport Report { get; set; } = new()
    {
        OverallStatus = HealthStatus.Healthy,
        Items = Array.Empty<HealthCheckItem>(),
        CheckedAtUtc = DateTimeOffset.UtcNow
    };

    public int CallCount => _calls;

    public Task<HealthCheckReport> CheckAsync(string? configPath, CancellationToken cancellationToken = default)
    {
        var call = Interlocked.Increment(ref _calls);
        if (ThrowOnCall != 0 && call == ThrowOnCall)
        {
            throw new InvalidOperationException("Simulated unexpected health-check failure.");
        }
        return Task.FromResult(Report);
    }
}
