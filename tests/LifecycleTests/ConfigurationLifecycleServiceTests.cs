using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;
using Xunit;

namespace SecureTunnel.GatewayAgent.LifecycleTests;

public sealed class ConfigurationLifecycleServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly MockSystemCommandExecutor _mock = new();
    private readonly GatewayConfiguration _config;
    private readonly ConfigurationLifecycleService _lifecycle;
    private readonly PeerService _peerService;
    private readonly ResourceService _resourceService;
    private readonly PolicyService _policyService;

    public ConfigurationLifecycleServiceTests()
    {
        _config = TestConfigurationFactory.CreateValid();
        _config.PeerStorePath = TempPath();
        _config.ResourceStorePath = TempPath();
        _config.PolicyStorePath = TempPath();
        _config.ConfigurationHistoryPath = TempPath();
        _config.OperationLockPath = TempPath();
        _config.FirewallRulesetPath = TempPath();
        _config.WireGuard.ConfigOutputPath = TempPath();
        _config.WireGuard.PrivateKeyPath = TempPath();
        File.WriteAllText(_config.WireGuard.PrivateKeyPath, "FAKE_TEST_SERVER_PRIVATE_KEY=");

        SetAllSuccessHandlers();

        _peerService = new PeerService(new JsonFilePeerRepository(NullLogger<JsonFilePeerRepository>.Instance), new Ipv4VpnIpAllocator(), NullLogger<PeerService>.Instance);
        _resourceService = new ResourceService(new JsonFileResourceRepository(NullLogger<JsonFileResourceRepository>.Instance), NullLogger<ResourceService>.Instance);
        _policyService = new PolicyService(new JsonFilePolicyRepository(NullLogger<JsonFilePolicyRepository>.Instance), _peerService, _resourceService, NullLogger<PolicyService>.Instance);

        var wgGenerator = new WireGuardConfigGenerator(new GatewayConfigurationValidator(), NullLogger<WireGuardConfigGenerator>.Instance);
        var wgService = new WireGuardService(_mock, NullLogger<WireGuardService>.Instance);
        var fwGenerator = new FirewallRuleGenerator(NullLogger<FirewallRuleGenerator>.Instance);
        var fwService = new FirewallService(_mock, NullLogger<FirewallService>.Instance);
        var fwOrchestrator = new FirewallApplyOrchestrator(fwGenerator, fwService, NullLogger<FirewallApplyOrchestrator>.Instance);

        _lifecycle = new ConfigurationLifecycleService(
            new JsonFileConfigurationHistoryRepository(NullLogger<JsonFileConfigurationHistoryRepository>.Instance),
            new FileOperationLockFactory(NullLogger<FileOperationLockFactory>.Instance),
            _peerService, _resourceService, _policyService,
            new GatewayConfigurationValidator(),
            wgGenerator, wgService, fwGenerator, fwOrchestrator, fwService,
            NullLogger<ConfigurationLifecycleService>.Instance,
            lockTimeout: TimeSpan.FromMilliseconds(300)); // keep the lock-contention test fast; production default stays 30s
    }

    // --- Desired -> Candidate -> Active ---

    [Fact]
    public async Task ApplyAsync_EmptyRegistries_ReachesActive()
    {
        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.True(result.Success);
        Assert.Equal(ConfigurationState.Active, result.State);
        Assert.Equal(1, result.Version);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Equal(1, history.ActiveVersion);
    }

    [Fact]
    public async Task ApplyAsync_DryRun_DoesNotPersistHistoryOrTouchSystem()
    {
        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Equal(ConfigurationState.Validated, result.State);
        Assert.False(File.Exists(_config.ConfigurationHistoryPath));
        Assert.Empty(_mock.Invocations);
    }

    [Fact]
    public async Task ApplyAsync_InvalidGatewayConfiguration_ValidationFailed_ActiveUnchanged()
    {
        _config.Security.FailClosed = false; // makes GatewayConfigurationValidator reject it

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(ConfigurationState.ValidationFailed, result.State);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Null(history.ActiveVersion);
        Assert.Single(history.Versions); // recorded for audit even though invalid
        Assert.Empty(_mock.Invocations); // never touched the system
    }

    [Fact]
    public async Task ApplyAsync_TwiceSuccessfully_SecondBecomesActiveFirstBecomesLastKnownGood()
    {
        var first = await _lifecycle.ApplyAsync(_config, "first", dryRun: false);
        Assert.True(first.Success);

        var second = await _lifecycle.ApplyAsync(_config, "second", dryRun: false);
        Assert.True(second.Success);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Equal(2, history.ActiveVersion);
        Assert.Equal(1, history.LastKnownGoodVersion);
    }

    [Fact]
    public async Task ApplyAsync_WireGuardRestartFails_ApplyFailed_ActiveUnchanged_FirewallNeverTouched()
    {
        _mock.Handlers["wg-quick"] = _ => MockSystemCommandExecutor.Failure(1, "wg-quick: address already in use");

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(ConfigurationState.ApplyFailed, result.State);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Null(history.ActiveVersion);
        Assert.DoesNotContain(_mock.Invocations, i => i.Command == "nft"); // firewall leg never attempted
    }

    [Fact]
    public async Task ApplyAsync_WireGuardSucceedsFirewallSyntaxFails_EffectiveStateUnknown_ActiveUnchanged()
    {
        _mock.Handlers["nft"] = req => req.Arguments.Contains("-c")
            ? MockSystemCommandExecutor.Failure(1, "syntax error")
            : MockSystemCommandExecutor.Success();

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(ConfigurationState.EffectiveStateUnknown, result.State);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Null(history.ActiveVersion);
        var v1 = history.Versions.Single(v => v.Version == 1);
        Assert.True(v1.WireGuardApplied, "WireGuard leg succeeded before the firewall leg failed");
        Assert.False(v1.FirewallApplied);
        Assert.Contains("WireGuard applied successfully, but nftables apply failed", v1.FailureReason);
    }

    [Fact]
    public async Task ApplyAsync_VerificationFindsFirewallTableMissing_VerificationFailed()
    {
        _mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "-f") return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "list") return MockSystemCommandExecutor.Failure(1, "No such file or directory");
            return MockSystemCommandExecutor.Success();
        };

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.True(result.State is ConfigurationState.VerificationFailed or ConfigurationState.EffectiveStateUnknown);

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Null(history.ActiveVersion);
    }

    [Fact]
    public async Task ApplyAsync_NftNotInstalled_ReportsBlockedNotFalseSuccess()
    {
        _mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("not found");

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("BLOCKED", result.Message);
    }

    // --- Concurrency ---

    [Fact]
    public async Task ApplyAsync_LockAlreadyHeld_RejectsConcurrentApply()
    {
        var lockFactory = new FileOperationLockFactory(NullLogger<FileOperationLockFactory>.Instance);
        using var externalLock = await lockFactory.AcquireAsync(_config.OperationLockPath, TimeSpan.FromSeconds(2));
        Assert.True(externalLock.Acquired);

        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(ConfigurationState.ApplyFailed, result.State);
        Assert.Empty(_mock.Invocations);
    }

    // --- Rollback ---

    [Fact]
    public async Task RollbackAsync_ToNeverAppliedVersion_Rejected()
    {
        _config.Security.FailClosed = false;
        var failed = await _lifecycle.ApplyAsync(_config, "bad", dryRun: false);
        Assert.False(failed.Success);

        var rollback = await _lifecycle.RollbackAsync(_config, failed.Version!.Value, dryRun: false);

        Assert.False(rollback.Success);
        Assert.Equal(ConfigurationState.ValidationFailed, rollback.State);
    }

    [Fact]
    public async Task RollbackAsync_ToUnknownVersion_Rejected()
    {
        var result = await _lifecycle.RollbackAsync(_config, 999, dryRun: false);

        Assert.False(result.Success);
    }

    [Fact]
    public async Task RollbackAsync_ToValidVersion_CreatesNewActiveVersion()
    {
        var v1 = await _lifecycle.ApplyAsync(_config, "v1", dryRun: false);
        Assert.True(v1.Success);

        // Add a peer and apply v2, so v1 and v2 have genuinely different content.
        await _peerService.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);
        var v2 = await _lifecycle.ApplyAsync(_config, "v2", dryRun: false);
        Assert.True(v2.Success);

        var rollback = await _lifecycle.RollbackAsync(_config, 1, dryRun: false);

        Assert.True(rollback.Success);
        Assert.Equal(ConfigurationState.RollbackSucceeded, rollback.State);
        Assert.Equal(3, rollback.Version); // rollback creates a NEW version, never rewrites v1

        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Equal(3, history.ActiveVersion);
        var v3 = history.Versions.Single(v => v.Version == 3);
        Assert.Empty(v3.Peers); // v3 restored v1's (empty) peer snapshot, not v2's live-registry peer
        Assert.Equal(1, v3.RollbackTargetVersion);
    }

    [Fact]
    public async Task RollbackAsync_UsesSnapshotData_NotLiveRegistryChangedAfterward()
    {
        var v1 = await _lifecycle.ApplyAsync(_config, "v1", dryRun: false);
        Assert.True(v1.Success);

        // Mutate the LIVE registry after v1's snapshot was captured.
        await _peerService.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var rollback = await _lifecycle.RollbackAsync(_config, 1, dryRun: false);

        Assert.True(rollback.Success);
        var history = await _lifecycle.GetHistoryAsync(_config);
        var newVersion = history.Versions.Single(v => v.Version == rollback.Version);
        Assert.Empty(newVersion.Peers); // must reflect v1's snapshot (no peers), not the live registry (which now has Alice)
    }

    [Fact]
    public async Task RollbackAsync_DryRun_DoesNotCreateNewVersion()
    {
        var v1 = await _lifecycle.ApplyAsync(_config, "v1", dryRun: false);
        Assert.True(v1.Success);

        var rollback = await _lifecycle.RollbackAsync(_config, 1, dryRun: true);

        Assert.True(rollback.Success);
        Assert.True(rollback.DryRun);
        var history = await _lifecycle.GetHistoryAsync(_config);
        Assert.Single(history.Versions); // still just v1
    }

    // --- Crash recovery ---

    [Fact]
    public async Task DetectIncompleteOperationAsync_NoHistory_ReturnsNull()
    {
        var result = await _lifecycle.DetectIncompleteOperationAsync(_config);

        Assert.Null(result);
    }

    [Fact]
    public async Task DetectIncompleteOperationAsync_LastVersionStuckApplying_ReturnsWarning()
    {
        var repository = new JsonFileConfigurationHistoryRepository(NullLogger<JsonFileConfigurationHistoryRepository>.Instance);
        var history = new ConfigurationHistory();
        history.Versions.Add(new ConfigurationSnapshot
        {
            Version = 1,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            SourceReason = "interrupted",
            ContentHash = "x",
            State = ConfigurationState.Applying,
            Peers = Array.Empty<Peer>(),
            Resources = Array.Empty<ProtectedResource>(),
            Policies = Array.Empty<AccessPolicy>(),
            EffectiveWireGuardPeerCount = 0,
            EffectiveFirewallRuleCount = 0
        });
        await repository.SaveAsync(_config.ConfigurationHistoryPath, history);

        var result = await _lifecycle.DetectIncompleteOperationAsync(_config);

        Assert.NotNull(result);
        Assert.Contains("interrupted", result, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DetectIncompleteOperationAsync_LastVersionActive_ReturnsNull()
    {
        var result1 = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);
        Assert.True(result1.Success);

        var result = await _lifecycle.DetectIncompleteOperationAsync(_config);

        Assert.Null(result);
    }

    // --- Retention ---

    [Fact]
    public async Task ApplyAsync_ManyVersions_PrunesOldOnesButKeepsActiveAndFirstVersion()
    {
        for (var i = 0; i < 35; i++)
        {
            var result = await _lifecycle.ApplyAsync(_config, $"apply {i}", dryRun: false);
            Assert.True(result.Success);
        }

        var history = await _lifecycle.GetHistoryAsync(_config);

        Assert.True(history.Versions.Count <= 31, "history should be pruned to roughly the retention limit");
        Assert.Contains(history.Versions, v => v.Version == history.ActiveVersion);
        Assert.Equal(35, history.ActiveVersion);
    }

    // --- Registry staleness (Phase 6: Desired vs Active drift detection) ---

    [Fact]
    public async Task IsDesiredStaleAsync_NothingEverApplied_ReturnsTrue()
    {
        var stale = await _lifecycle.IsDesiredStaleAsync(_config);

        Assert.True(stale, "with no Active version at all, Desired trivially differs from 'nothing'");
    }

    [Fact]
    public async Task IsDesiredStaleAsync_RightAfterApply_ReturnsFalse()
    {
        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);
        Assert.True(result.Success);

        var stale = await _lifecycle.IsDesiredStaleAsync(_config);

        Assert.False(stale);
    }

    [Fact]
    public async Task IsDesiredStaleAsync_AfterRegistryChangeSinceApply_ReturnsTrue()
    {
        var result = await _lifecycle.ApplyAsync(_config, "test", dryRun: false);
        Assert.True(result.Success);

        await _peerService.AddAsync(_config, "Alice", ValidKey(1), null, null, dryRun: false);

        var stale = await _lifecycle.IsDesiredStaleAsync(_config);

        Assert.True(stale, "a peer was added after the last apply, so Desired now differs from Active");
    }

    // --- Startup recovery scenarios (Phase 6) ---

    [Fact]
    public async Task DetectIncompleteOperationAsync_InterruptedRollback_ReturnsWarning()
    {
        var repository = new JsonFileConfigurationHistoryRepository(NullLogger<JsonFileConfigurationHistoryRepository>.Instance);
        var history = new ConfigurationHistory { ActiveVersion = 1 };
        history.Versions.Add(MakeMinimalSnapshot(1, ConfigurationState.Active));
        history.Versions.Add(MakeMinimalSnapshot(2, ConfigurationState.RollbackPending));
        await repository.SaveAsync(_config.ConfigurationHistoryPath, history);

        var result = await _lifecycle.DetectIncompleteOperationAsync(_config);

        Assert.NotNull(result);
    }

    [Fact]
    public async Task DetectIncompleteOperationAsync_CorruptHistoryFile_ReturnsWarningNotCrash()
    {
        await File.WriteAllTextAsync(_config.ConfigurationHistoryPath, "{ not valid json [[[");

        var result = await _lifecycle.DetectIncompleteOperationAsync(_config);

        Assert.NotNull(result); // must surface the problem, never silently report "all clear"
    }

    [Fact]
    public async Task GetHistoryAsync_ActiveVersionPointsToMissingSnapshot_DoesNotCrash()
    {
        // Simulates a hand-edited or otherwise inconsistent history file: ActiveVersion
        // references a version number that isn't actually in the Versions list.
        var repository = new JsonFileConfigurationHistoryRepository(NullLogger<JsonFileConfigurationHistoryRepository>.Instance);
        var history = new ConfigurationHistory { ActiveVersion = 99 };
        history.Versions.Add(MakeMinimalSnapshot(1, ConfigurationState.Active));
        await repository.SaveAsync(_config.ConfigurationHistoryPath, history);

        var stale = await _lifecycle.IsDesiredStaleAsync(_config);
        var loaded = await _lifecycle.GetHistoryAsync(_config);

        Assert.True(stale, "an Active pointer with no matching snapshot must be treated as 'cannot confirm in sync', never as trusted");
        Assert.Equal(99, loaded.ActiveVersion);
    }

    private static ConfigurationSnapshot MakeMinimalSnapshot(int version, ConfigurationState state) => new()
    {
        Version = version,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        SourceReason = "test",
        ContentHash = "x",
        State = state,
        Peers = Array.Empty<Peer>(),
        Resources = Array.Empty<ProtectedResource>(),
        Policies = Array.Empty<AccessPolicy>(),
        EffectiveWireGuardPeerCount = 0,
        EffectiveFirewallRuleCount = 0
    };

    // --- Verify ---

    [Fact]
    public async Task VerifyAsync_AllUp_ReportsKnownAndHealthy()
    {
        var result = await _lifecycle.VerifyAsync(_config);

        Assert.True(result.WireGuardUp);
        Assert.True(result.FirewallTablePresent);
        Assert.True(result.EffectiveStateKnown);
    }

    [Fact]
    public async Task VerifyAsync_ToolsMissing_ReportsUnknownNotFalseHealthy()
    {
        _mock.Handlers["wg"] = _ => MockSystemCommandExecutor.NotFound("not found");
        _mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("not found");

        var result = await _lifecycle.VerifyAsync(_config);

        Assert.False(result.EffectiveStateKnown);
    }

    private void SetAllSuccessHandlers()
    {
        _mock.Handlers["wg"] = req =>
        {
            if (req.Arguments.Contains("--version")) return MockSystemCommandExecutor.Success("wg 1.0.0");
            if (req.Arguments.Contains("show")) return MockSystemCommandExecutor.Success("interface: wg-securetunnel\n");
            return MockSystemCommandExecutor.Success();
        };
        _mock.Handlers["wg-quick"] = _ => MockSystemCommandExecutor.Success();
        _mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments.Count > 0 && req.Arguments[0] == "-f") return MockSystemCommandExecutor.Success();
            if (req.Arguments.Contains("list")) return MockSystemCommandExecutor.Success("table inet securetunnel { }");
            return MockSystemCommandExecutor.Success();
        };
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-lifecycle-{Guid.NewGuid():N}");
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            foreach (var suffix in new[] { "", ".candidate", ".lastknowngood" })
            {
                try { if (File.Exists(f + suffix)) File.Delete(f + suffix); } catch { /* best-effort */ }
            }
        }
    }
}
