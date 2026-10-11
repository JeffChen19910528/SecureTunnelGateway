using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Daemon;

/// <summary>
/// Phase 6A: the persistent `gateway serve` execution mode. Deliberately NOT a Control
/// Plane / admin API - it exposes no network endpoint of any kind. Its only two jobs are
/// (1) run the same startup/crash-recovery diagnostics `gateway status`/`doctor` already
/// expose, on a schedule, so problems are visible in journald without an operator polling,
/// and (2) never let an unattended process silently widen access or fake a success.
///
/// Startup classification (see EvaluateAsync): only two things are ever Failed (fatal,
/// process exits non-zero, no loop entered) - configuration that cannot even be loaded, and
/// an unexpected exception. Every other documented "something is wrong" condition
/// (invalid configuration, a missing tool, an unusable key, an interrupted prior operation,
/// an indeterminate effective state, a stale Desired-vs-Active) is Blocked or Degraded: the
/// process stays up and keeps reporting the condition on every tick, rather than
/// crash-looping under systemd's Restart=on-failure. This is a deliberate deviation from a
/// literal reading of the Phase 6A spec (which lists "configuration invalid" under Blocked
/// but also separately defines Failed as any "fatal initialization error") - reusing the
/// existing IHealthCheckService/IConfigurationLifecycleService abstractions unchanged was
/// judged more valuable than inventing a second, slightly different classification of the
/// same underlying signals. See the Phase 6A completion report for the full rationale.
///
/// Registry-changes-trigger-apply (spec section 7): Option A was chosen - the daemon only
/// logs that Desired has drifted from Active (via IsDesiredStaleAsync); it never calls
/// `ConfigurationLifecycleService.ApplyAsync` itself. An operator (or a future, explicitly
/// separate automation) must run `config apply`. This keeps "no allow-all fallback" and "no
/// uncontrolled automatic apply" trivially true by construction.
/// </summary>
public sealed class GatewayDaemonService : IGatewayDaemonService
{
    private readonly IConfigurationLoader _configurationLoader;
    private readonly IHealthCheckService _healthCheckService;
    private readonly IConfigurationLifecycleService _lifecycleService;
    private readonly IDaemonTicker _ticker;
    private readonly ILogger<GatewayDaemonService> _logger;

    public GatewayDaemonService(
        IConfigurationLoader configurationLoader,
        IHealthCheckService healthCheckService,
        IConfigurationLifecycleService lifecycleService,
        IDaemonTicker ticker,
        ILogger<GatewayDaemonService> logger)
    {
        _configurationLoader = configurationLoader;
        _healthCheckService = healthCheckService;
        _lifecycleService = lifecycleService;
        _ticker = ticker;
        _logger = logger;
    }

    public async Task<int> RunAsync(string configPath, DaemonRunOptions options, CancellationToken cancellationToken)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var sigterm = TryRegisterSignal(PosixSignal.SIGTERM, linkedCts);
        using var sigint = TryRegisterSignal(PosixSignal.SIGINT, linkedCts);

        _logger.LogInformation(
            "SecureTunnel Gateway daemon starting (config={ConfigPath}, interval={IntervalSeconds}s, once={RunOnce})",
            configPath, options.HealthCheckInterval.TotalSeconds, options.RunOnce);

        GatewayConfiguration config;
        try
        {
            config = _configurationLoader.Load(configPath);
        }
        catch (Exception ex)
        {
            var failed = new DaemonStartupResult { Status = DaemonStartupStatus.Failed, Message = $"Failed to load configuration '{configPath}': {ex.Message}" };
            LogResult(failed);
            return ExitCodes.ValidationFailure;
        }

        DaemonStartupResult startup;
        try
        {
            startup = await EvaluateAsync(config, configPath, linkedCts.Token);
        }
        catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
        {
            _logger.LogInformation("SecureTunnel Gateway daemon stopped during startup diagnostics (signal received).");
            return ExitCodes.Success;
        }
        catch (Exception ex)
        {
            var failed = new DaemonStartupResult { Status = DaemonStartupStatus.Failed, Message = $"Unexpected error during startup diagnostics: {ex.Message}" };
            LogResult(failed);
            return ExitCodes.GeneralFailure;
        }

        LogResult(startup);

        if (startup.Status == DaemonStartupStatus.Failed)
        {
            return ExitCodes.GeneralFailure;
        }

        if (options.RunOnce)
        {
            _logger.LogInformation("--once specified: startup diagnostics complete, exiting without entering the run loop.");
            return startup.Status == DaemonStartupStatus.Blocked ? ExitCodes.GeneralFailure : ExitCodes.Success;
        }

        await RunLoopAsync(config, configPath, options, linkedCts.Token);
        _logger.LogInformation("SecureTunnel Gateway daemon stopped gracefully.");
        return ExitCodes.Success;
    }

    private async Task RunLoopAsync(GatewayConfiguration config, string configPath, DaemonRunOptions options, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await _ticker.WaitForNextTickAsync(options.HealthCheckInterval, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }

            if (cancellationToken.IsCancellationRequested)
            {
                break;
            }

            try
            {
                var tick = await EvaluateAsync(config, configPath, cancellationToken);
                LogResult(tick);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                // A transient failure evaluating state (e.g. a momentary I/O error) must never
                // crash the daemon or be reported as fatal - only the startup pass can exit
                // the process. Log and retry on the next tick.
                _logger.LogWarning(ex, "Transient error during periodic Gateway state check; will retry in {IntervalSeconds}s.", options.HealthCheckInterval.TotalSeconds);
            }
        }
    }

    /// <summary>
    /// Runs the same startup diagnostics on every tick (startup and periodic checks are
    /// identical in substance - the only difference is what RunAsync does with the result).
    /// Reuses IHealthCheckService/IConfigurationLifecycleService exactly as `gateway
    /// status`/`doctor` already do - see the class-level doc comment for why this
    /// classification differs from `gateway status`'s Healthy/Degraded/Blocked/Failed/Unknown.
    /// </summary>
    private async Task<DaemonStartupResult> EvaluateAsync(GatewayConfiguration config, string configPath, CancellationToken ct)
    {
        var health = await _healthCheckService.CheckAsync(configPath, ct);

        var missingTools = health.Items
            .Where(i => i.Id is "wireguard-command" or "nftables-command" && i.Status == CheckStatus.Blocked)
            .Select(i => i.Id)
            .ToList();
        var keyUnavailable = health.Items.Any(i => i.Id == "key-file-permissions" && i.Status == CheckStatus.Fail);
        var configInvalid = health.Items.Any(i => i.Id == "configuration-validity" && i.Status == CheckStatus.Fail);
        var permissionsUnavailable = health.Items.Any(i => i.Id == "root-permission" && i.Status == CheckStatus.Fail);

        string? incomplete;
        try
        {
            incomplete = await _lifecycleService.DetectIncompleteOperationAsync(config, ct);
        }
        catch (Exception ex)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = $"Could not determine incomplete-operation state: {ex.Message}" };
        }

        if (incomplete is not null)
        {
            // Crash recovery (spec section 5): never silently treat this as fine. Stay up so
            // the warning - with the version, detected state, and recommended operator
            // action already embedded in `incomplete` by ConfigurationLifecycleService - is
            // repeated on every tick until an operator resolves it.
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = incomplete, IncompleteOperation = incomplete };
        }

        if (missingTools.Count > 0)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = $"Required tool(s) unavailable: {string.Join(", ", missingTools)}." };
        }

        if (keyUnavailable)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = "WireGuard private key is unavailable or has unsafe permissions." };
        }

        if (configInvalid)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = "Configuration failed validation." };
        }

        if (permissionsUnavailable)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = "Required OS permissions are unavailable." };
        }

        ConfigurationVerifyResult verify;
        try
        {
            verify = await _lifecycleService.VerifyAsync(config, ct);
        }
        catch (Exception ex)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = $"Could not verify effective state: {ex.Message}" };
        }

        if (!verify.EffectiveStateKnown)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = $"Effective state cannot be safely determined: {verify.Message}" };
        }

        bool stale;
        try
        {
            stale = await _lifecycleService.IsDesiredStaleAsync(config, ct);
        }
        catch (Exception ex)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Blocked, Message = $"Could not determine Desired/Active drift: {ex.Message}" };
        }

        if (stale)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Degraded, Message = "Desired configuration has changed since the last successful `config apply` - a new apply is required to pick up the change (not performed automatically)." };
        }

        if (health.OverallStatus == HealthStatus.Degraded)
        {
            return new DaemonStartupResult { Status = DaemonStartupStatus.Degraded, Message = "One or more optional health checks reported a warning; see `gateway status`/`doctor` for details." };
        }

        return new DaemonStartupResult { Status = DaemonStartupStatus.Healthy, Message = "All startup checks passed." };
    }

    private void LogResult(DaemonStartupResult result)
    {
        switch (result.Status)
        {
            case DaemonStartupStatus.Healthy:
                _logger.LogInformation("Gateway state: Healthy. {Message}", result.Message);
                break;
            case DaemonStartupStatus.Degraded:
                _logger.LogWarning("Gateway state: Degraded. {Message}", result.Message);
                break;
            case DaemonStartupStatus.Blocked:
                _logger.LogWarning("Gateway state: Blocked. {Message}", result.Message);
                break;
            case DaemonStartupStatus.Failed:
                _logger.LogCritical("Gateway state: Failed. {Message}", result.Message);
                break;
        }
    }

    /// <summary>
    /// SIGINT is already handled by System.CommandLine's own cancellation wiring (Ctrl+C ->
    /// the CancellationToken InvokeAsync hands to the command action). SIGTERM - what
    /// `systemctl stop` actually sends - is not, so it is registered explicitly here.
    /// Guarded because PosixSignalRegistration support for SIGTERM is platform-dependent
    /// (this project is developed on Windows/WSL2 - see docs/troubleshooting.md); a platform
    /// that cannot register it simply relies on SIGINT/the parent process token instead.
    /// </summary>
    private static PosixSignalRegistration? TryRegisterSignal(PosixSignal signal, CancellationTokenSource cts)
    {
        try
        {
            return PosixSignalRegistration.Create(signal, context =>
            {
                context.Cancel = true;
                try { cts.Cancel(); } catch (ObjectDisposedException) { }
            });
        }
        catch (PlatformNotSupportedException)
        {
            return null;
        }
    }
}
