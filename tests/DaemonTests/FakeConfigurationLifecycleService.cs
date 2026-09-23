using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.DaemonTests;

/// <summary>
/// Test double for <see cref="IConfigurationLifecycleService"/> that lets each daemon test
/// control exactly what DetectIncompleteOperationAsync/VerifyAsync/IsDesiredStaleAsync
/// report, without having to drive a real apply/rollback pipeline through mocked wg/nft
/// commands. ApplyAsync/RollbackAsync throw if ever called - the daemon must never call
/// them (Option A, see GatewayDaemonService's class doc comment), so a test hitting this
/// exception is itself proof of a regression.
/// </summary>
public sealed class FakeConfigurationLifecycleService : IConfigurationLifecycleService
{
    public Func<CancellationToken, Task<string?>> DetectIncompleteOperation { get; set; } = _ => Task.FromResult<string?>(null);

    public Func<CancellationToken, Task<ConfigurationVerifyResult>> Verify { get; set; } =
        _ => Task.FromResult(new ConfigurationVerifyResult { WireGuardUp = true, FirewallTablePresent = true, EffectiveStateKnown = true, Message = "OK" });

    public Func<CancellationToken, Task<bool>> IsDesiredStale { get; set; } = _ => Task.FromResult(false);

    public int DetectIncompleteOperationCallCount { get; private set; }
    public int VerifyCallCount { get; private set; }
    public int IsDesiredStaleCallCount { get; private set; }

    public Task<string?> DetectIncompleteOperationAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        DetectIncompleteOperationCallCount++;
        return DetectIncompleteOperation(cancellationToken);
    }

    public Task<ConfigurationVerifyResult> VerifyAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        VerifyCallCount++;
        return Verify(cancellationToken);
    }

    public Task<bool> IsDesiredStaleAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        IsDesiredStaleCallCount++;
        return IsDesiredStale(cancellationToken);
    }

    public Task<ConfigurationHistory> GetHistoryAsync(GatewayConfiguration config, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException("The daemon must never need GetHistoryAsync directly.");

    public Task<ConfigurationSnapshot?> GetVersionAsync(GatewayConfiguration config, int version, CancellationToken cancellationToken = default) =>
        throw new NotImplementedException("The daemon must never need GetVersionAsync directly.");

    public Task<ConfigurationApplyResult> ApplyAsync(GatewayConfiguration config, string sourceReason, bool dryRun, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("The daemon must never call ApplyAsync automatically (see GatewayDaemonService doc comment, Option A).");

    public Task<ConfigurationApplyResult> RollbackAsync(GatewayConfiguration config, int targetVersion, bool dryRun, CancellationToken cancellationToken = default) =>
        throw new InvalidOperationException("The daemon must never call RollbackAsync automatically.");
}
