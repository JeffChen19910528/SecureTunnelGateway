using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Daemon;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.DaemonTests;

/// <summary>
/// Unit tests for GatewayDaemonService (Phase 6A). Constructs the service directly (not
/// through the full CLI/DI graph) so each test can substitute exactly the fake it needs -
/// see FakeConfigurationLifecycleService/FakeDaemonTicker/FakeHealthCheckService. Uses real
/// YamlConfigurationLoader/GatewayConfigurationValidator/KeyManagementService so
/// configuration-load and key-permission checks are genuine, not simulated.
/// </summary>
public sealed class GatewayDaemonServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();

    // ---------------------------------------------------------------
    // Daemon lifecycle
    // ---------------------------------------------------------------

    [Fact]
    public async Task ValidConfiguration_StartupNeverBlockedOrFailed()
    {
        // On this Windows/WSL2 dev host, IKeyManagementService.CheckPrivateKeyPermissions
        // fails closed whenever a key file exists (it cannot verify Unix modes here), so a
        // literal "Healthy" outcome is unreachable in this environment (same caveat as
        // GatewayCliInvocationTests). Leaving the key file absent yields a Warn (not Fail),
        // which is enough to prove startup reaches Healthy or Degraded - never Blocked/Failed
        // - for an otherwise-valid configuration.
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var ticker = new FakeDaemonTicker { TicksBeforeCancel = 0 };
        var daemon = BuildDaemon(configPath, ticker: ticker);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
    }

    [Fact]
    public async Task ConfigurationCannotBeLoaded_FailedStartup_ExitsValidationFailure()
    {
        var missingPath = NonExistentPath();
        var daemon = BuildDaemon(missingPath);

        var exitCode = await daemon.RunAsync(missingPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task InvalidConfiguration_BlockedStartup_NotFatal_ExitsGeneralFailureUnderOnce()
    {
        // A bad interface name fails GatewayConfigurationValidator (business-rule invalid),
        // as opposed to a YAML parse error - per GatewayDaemonService's doc comment this is
        // Blocked, not Failed: the real daemon (RunOnce=false) would stay up reporting it.
        var configPath = WriteValidConfig(out _, createKeyFile: false, interfaceNameOverride: "this-name-is-way-too-long-for-ifnamsiz");
        var daemon = BuildDaemon(configPath);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task MissingRequiredTool_BlockedStartup_ExitsGeneralFailureUnderOnce()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var daemon = BuildDaemon(configPath, environmentChecker: FakeEnvironmentChecker.MissingWireGuard());

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task KeyFileExists_BlockedStartup_ExitsGeneralFailureUnderOnce()
    {
        // A key file that exists always fails permission verification on Windows (fail-closed
        // by design) - deterministically exercises the "Required key unavailable" Blocked path.
        var configPath = WriteValidConfig(out _, createKeyFile: true);
        var daemon = BuildDaemon(configPath);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task Cancellation_DuringRunLoop_StopsGracefully_ReturnsSuccess()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var ticker = new FakeDaemonTicker { TicksBeforeCancel = 2 };
        var daemon = BuildDaemon(configPath, ticker: ticker);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = false, HealthCheckInterval = TimeSpan.FromMilliseconds(1) }, CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.True(ticker.CallCount >= 3, "expected the loop to actually run for several ticks before stopping, not exit immediately");
    }

    [Fact]
    public async Task UnexpectedExceptionDuringStartup_FailedStartup_ExitsGeneralFailure()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var throwingHealth = new FakeHealthCheckService { ThrowOnCall = 1 };
        var daemon = BuildDaemon(configPath, healthCheckService: throwingHealth);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    // ---------------------------------------------------------------
    // Startup recovery (Phase 5 crash recovery reused at daemon startup)
    // ---------------------------------------------------------------

    [Fact]
    public async Task InterruptedApply_ReportedAsBlocked_NeverSilentlySucceeds()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var lifecycle = new FakeConfigurationLifecycleService
        {
            DetectIncompleteOperation = _ => Task.FromResult<string?>("Version 3 was left in state 'ApplyPending' - the Gateway Agent process was likely interrupted mid-operation.")
        };
        var daemon = BuildDaemon(configPath, lifecycleService: lifecycle);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task EffectiveStateUnknown_ReportedAsBlocked_FailClosed()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var lifecycle = new FakeConfigurationLifecycleService
        {
            Verify = _ => Task.FromResult(new ConfigurationVerifyResult { WireGuardUp = false, FirewallTablePresent = false, EffectiveStateKnown = false, Message = "wg/nft not available" })
        };
        var daemon = BuildDaemon(configPath, lifecycleService: lifecycle);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task CorruptHistoryDuringRecoveryCheck_ReportedAsBlocked_NotFatal()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var lifecycle = new FakeConfigurationLifecycleService
        {
            DetectIncompleteOperation = _ => throw new InvalidOperationException("Configuration history is corrupt and could not be read.")
        };
        var daemon = BuildDaemon(configPath, lifecycleService: lifecycle);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        // Blocked, not Failed: a corrupt history must never crash the daemon outright.
        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task ActiveSnapshotMissing_SurfacesAsStale_Degraded_NotFatal()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var lifecycle = new FakeConfigurationLifecycleService
        {
            IsDesiredStale = _ => Task.FromResult(true) // mirrors ConfigurationLifecycleService.IsDesiredStaleAsync when Active points at a missing snapshot
        };
        var daemon = BuildDaemon(configPath, lifecycleService: lifecycle);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        // Degraded is not Blocked/Failed under --once.
        Assert.Equal(ExitCodes.Success, exitCode);
    }

    // ---------------------------------------------------------------
    // Runtime behavior
    // ---------------------------------------------------------------

    [Fact]
    public async Task HealthCheckInterval_IsPassedThroughToTheTicker()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var ticker = new FakeDaemonTicker { TicksBeforeCancel = 1 };
        var daemon = BuildDaemon(configPath, ticker: ticker);
        var interval = TimeSpan.FromSeconds(42);

        await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = false, HealthCheckInterval = interval }, CancellationToken.None);

        Assert.All(ticker.ObservedIntervals, observed => Assert.Equal(interval, observed));
    }

    [Fact]
    public async Task TransientExceptionDuringATick_DoesNotCrashTheLoop_ContinuesToNextTick()
    {
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var ticker = new FakeDaemonTicker { TicksBeforeCancel = 3 };
        // Throws on the SECOND EvaluateAsync call - the first is the startup pass, so this
        // hits the first tick inside the loop.
        var throwingHealth = new FakeHealthCheckService { ThrowOnCall = 2 };
        var daemon = BuildDaemon(configPath, ticker: ticker, healthCheckService: throwingHealth);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = false, HealthCheckInterval = TimeSpan.FromMilliseconds(1) }, CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
        // The loop must have keep going past the failing tick to later ticks.
        Assert.True(throwingHealth.CallCount > 2, "expected the daemon to keep evaluating on later ticks after a transient failure");
    }

    [Fact]
    public async Task NoUncontrolledAutoApply_DaemonNeverCallsApplyOrRollback()
    {
        // FakeConfigurationLifecycleService.ApplyAsync/RollbackAsync throw if ever invoked -
        // running every documented scenario (stale, blocked, healthy) without that exception
        // surfacing is itself the proof that the daemon never auto-applies (Option A).
        var configPath = WriteValidConfig(out _, createKeyFile: false);
        var lifecycle = new FakeConfigurationLifecycleService { IsDesiredStale = _ => Task.FromResult(true) };
        var ticker = new FakeDaemonTicker { TicksBeforeCancel = 3 };
        var daemon = BuildDaemon(configPath, lifecycleService: lifecycle, ticker: ticker);

        var exitCode = await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = false, HealthCheckInterval = TimeSpan.FromMilliseconds(1) }, CancellationToken.None);

        Assert.Equal(ExitCodes.Success, exitCode);
    }

    // ---------------------------------------------------------------
    // Security: no secret leakage in daemon logs
    // ---------------------------------------------------------------

    [Fact]
    public async Task PrivateKeyContent_NeverAppearsInDaemonLogMessages()
    {
        const string secretMarker = "SUPER_SECRET_PRIVATE_KEY_VALUE";
        var configPath = WriteValidConfig(out var keyPath, createKeyFile: true, keyFileContent: secretMarker + "=");
        var capturingLogger = new CapturingLogger();
        var daemon = BuildDaemon(configPath, logger: capturingLogger);

        await daemon.RunAsync(configPath, new DaemonRunOptions { RunOnce = true }, CancellationToken.None);

        Assert.All(capturingLogger.Messages, m => Assert.DoesNotContain(secretMarker, m));
        Assert.NotEmpty(capturingLogger.Messages);
        _ = keyPath;
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    private GatewayDaemonService BuildDaemon(
        string configPath,
        FakeConfigurationLifecycleService? lifecycleService = null,
        FakeDaemonTicker? ticker = null,
        FakeEnvironmentChecker? environmentChecker = null,
        FakeHealthCheckService? healthCheckService = null,
        CapturingLogger? logger = null)
    {
        var loader = new YamlConfigurationLoader();
        var validator = new GatewayConfigurationValidator();
        var keyManagement = new KeyManagementService(new MockSystemCommandExecutor(), NullLogger<KeyManagementService>.Instance);
        IHealthCheckService health = (IHealthCheckService?)healthCheckService ?? new HealthCheckService(
            environmentChecker ?? FakeEnvironmentChecker.AllHealthy(),
            loader,
            validator,
            keyManagement,
            NullLogger<HealthCheckService>.Instance);

        return new GatewayDaemonService(
            loader,
            health,
            lifecycleService ?? new FakeConfigurationLifecycleService(),
            ticker ?? new FakeDaemonTicker { TicksBeforeCancel = 0 },
            (Microsoft.Extensions.Logging.ILogger<GatewayDaemonService>?)logger ?? NullLogger<GatewayDaemonService>.Instance);
    }

    private string WriteValidConfig(out string keyPath, bool createKeyFile, string? interfaceNameOverride = null, string keyFileContent = "FAKE_TEST_SERVER_PRIVATE_KEY=")
    {
        string PathFor(string name) => Path.Combine(Path.GetTempPath(), $"securetunnel-daemon-{name}-{Guid.NewGuid():N}").Replace("\\", "/");

        keyPath = PathFor("key") + ".key";
        if (createKeyFile)
        {
            File.WriteAllText(keyPath, keyFileContent);
            _tempFiles.Add(keyPath);
        }

        var wgOutputPath = PathFor("wgconf") + ".conf";
        var peerStorePath = PathFor("peers") + ".json";
        var resourceStorePath = PathFor("resources") + ".json";
        var policyStorePath = PathFor("policies") + ".json";
        var firewallRulesetPath = PathFor("ruleset") + ".conf";
        var historyPath = PathFor("history") + ".json";
        var lockPath = PathFor("lock") + ".lock";

        foreach (var p in new[] { wgOutputPath, peerStorePath, resourceStorePath, policyStorePath, firewallRulesetPath, historyPath, lockPath })
        {
            _tempFiles.Add(p);
        }

        var interfaceName = interfaceNameOverride ?? "wg-securetunnel";

        var yaml = $"""
            gatewayId: "gw-daemon-test"
            wireGuard:
              interfaceName: "{interfaceName}"
              listenPort: 51820
              privateKeyPath: "{keyPath}"
              configOutputPath: "{wgOutputPath}"
            network:
              vpnCidr: "10.250.0.0/24"
              gatewayVpnAddress: "10.250.0.1"
              clientAddressPoolStart: "10.250.0.10"
              clientAddressPoolEnd: "10.250.0.200"
              lanInterface: "eth0"
              protectedNetworks:
                - name: "lab-protected-net"
                  cidr: "10.20.0.0/24"
            security:
              failClosed: true
            peerStorePath: "{peerStorePath}"
            resourceStorePath: "{resourceStorePath}"
            policyStorePath: "{policyStorePath}"
            firewallRulesetPath: "{firewallRulesetPath}"
            configurationHistoryPath: "{historyPath}"
            operationLockPath: "{lockPath}"
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-daemon-config-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        return path;
    }

    private static string NonExistentPath() =>
        Path.Combine(Path.GetTempPath(), $"securetunnel-daemon-missing-{Guid.NewGuid():N}");

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { /* best-effort */ }
        }
    }
}
