using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class FirewallApplyOrchestratorTests : IDisposable
{
    private readonly List<string> _tempPaths = new();

    [Fact]
    public async Task ApplyAsync_InvalidConfiguration_FailsAtNotStarted_NeverCallsNft()
    {
        // FirewallRuleGenerator doesn't re-validate GatewayConfiguration itself (that's
        // GatewayConfigurationValidator's job); force a real generation-level failure via
        // two enabled policies that resolve to the exact same effective (peer, resource)
        // rule - the generator's duplicate-effective-rule check.
        var config = TestConfigurationFactory.CreateValid();
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var duplicate1 = MakePolicy("rule-1", "peer-1", "resource-1");
        var duplicate2 = MakePolicy("rule-2", "peer-1", "resource-1"); // same peer+resource -> generator flags as duplicate effective rule

        var mock = new MockSystemCommandExecutor();
        var orchestrator = new FirewallApplyOrchestrator(new FirewallRuleGenerator(NullLogger<FirewallRuleGenerator>.Instance),
            new FirewallService(mock, NullLogger<FirewallService>.Instance), NullLogger<FirewallApplyOrchestrator>.Instance);

        var result = await orchestrator.ApplyAsync(config, new[] { peer }, new[] { resource }, new[] { duplicate1, duplicate2 }, dryRun: false);

        Assert.False(result.Success);
        Assert.Equal(FirewallApplyState.Failed, result.State);
        Assert.Contains("NotStarted", result.Message);
        Assert.Empty(mock.Invocations);
    }

    [Fact]
    public async Task ApplyAsync_DryRun_StopsAtGenerated_NeverCallsNft()
    {
        var config = TestConfigurationFactory.CreateValid();
        var mock = new MockSystemCommandExecutor();
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: true);

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Equal(FirewallApplyState.Generated, result.State);
        Assert.Empty(mock.Invocations);
    }

    [Fact]
    public async Task ApplyAsync_SyntaxCheckFails_DoesNotTouchActiveFile_NeverCallsApply()
    {
        var config = ValidConfigWithPaths(out var activePath);
        await File.WriteAllTextAsync(activePath, "OLD-GOOD-RULESET");

        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = req => req.Arguments.Contains("-c")
            ? MockSystemCommandExecutor.Failure(1, "syntax error at line 5")
            : MockSystemCommandExecutor.Success();
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("Generated", result.Message);
        Assert.Equal("OLD-GOOD-RULESET", await File.ReadAllTextAsync(activePath));
        Assert.DoesNotContain(mock.Invocations, i => i.Arguments.Contains("-f") && !i.Arguments.Contains("-c"));
    }

    [Fact]
    public async Task ApplyAsync_ApplyFails_RestoresPreviousActiveFile()
    {
        var config = ValidConfigWithPaths(out var activePath);
        await File.WriteAllTextAsync(activePath, "OLD-GOOD-RULESET");

        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success(); // syntax OK
            if (req.Arguments[0] == "-f") return MockSystemCommandExecutor.Failure(1, "Error: apply failed");
            return MockSystemCommandExecutor.Success();
        };
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("SyntaxValidated", result.Message);
        Assert.Equal("OLD-GOOD-RULESET", await File.ReadAllTextAsync(activePath));
    }

    [Fact]
    public async Task ApplyAsync_ApplyFailsWithNoPriorActiveFile_RemovesPartialFile()
    {
        var config = ValidConfigWithPaths(out var activePath);
        Assert.False(File.Exists(activePath)); // first-ever apply, nothing to restore

        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "-f") return MockSystemCommandExecutor.Failure(1, "apply failed");
            return MockSystemCommandExecutor.Success();
        };
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: false);

        Assert.False(result.Success);
        Assert.False(File.Exists(activePath), "no prior active ruleset existed, so a failed apply must not leave a stray file behind");
    }

    [Fact]
    public async Task ApplyAsync_AppliedButVerificationDoesNotConfirmPresent_ReportsFailedNotSuccess()
    {
        var config = ValidConfigWithPaths(out _);

        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "-f") return MockSystemCommandExecutor.Success(); // apply reports success
            if (req.Arguments[0] == "list") return MockSystemCommandExecutor.Failure(1, "No such file or directory"); // but verify says NotPresent
            return MockSystemCommandExecutor.Success();
        };
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: false);

        Assert.False(result.Success, "must never report success when verification did not confirm the table is present");
        Assert.Contains("UNKNOWN", result.Message);
    }

    [Fact]
    public async Task ApplyAsync_FullSuccess_ReachesVerifiedState()
    {
        var config = ValidConfigWithPaths(out var activePath);
        var peer = MakePeer("peer-1", PeerStatus.Active, "10.250.0.10");
        var resource = MakeResource("resource-1", "10.20.0.10", 443);
        var policy = MakePolicy("rule-1", "peer-1", "resource-1");

        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "-f") return MockSystemCommandExecutor.Success();
            if (req.Arguments[0] == "list") return MockSystemCommandExecutor.Success("table inet securetunnel { ... }");
            return MockSystemCommandExecutor.Success();
        };
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, new[] { peer }, new[] { resource }, new[] { policy }, dryRun: false);

        Assert.True(result.Success);
        Assert.Equal(FirewallApplyState.Verified, result.State);
        Assert.True(File.Exists(activePath));
        Assert.Contains("10.250.0.10", await File.ReadAllTextAsync(activePath));
    }

    [Fact]
    public async Task ApplyAsync_NftNotInstalled_ReportsBlockedNotCrash()
    {
        var config = ValidConfigWithPaths(out _);
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("nft: command not found");
        var orchestrator = BuildOrchestrator(mock);

        var result = await orchestrator.ApplyAsync(config, Array.Empty<Peer>(), Array.Empty<ProtectedResource>(), Array.Empty<AccessPolicy>(), dryRun: false);

        Assert.False(result.Success);
        Assert.Contains("BLOCKED", result.Message);
    }

    private static FirewallApplyOrchestrator BuildOrchestrator(MockSystemCommandExecutor mock) =>
        new(new FirewallRuleGenerator(NullLogger<FirewallRuleGenerator>.Instance),
            new FirewallService(mock, NullLogger<FirewallService>.Instance),
            NullLogger<FirewallApplyOrchestrator>.Instance);

    private GatewayConfiguration ValidConfigWithPaths(out string activePath)
    {
        var config = TestConfigurationFactory.CreateValid();
        activePath = TempPath();
        config.FirewallRulesetPath = activePath;
        return config;
    }

    private static Peer MakePeer(string id, PeerStatus status, string vpnIp) => new()
    {
        PeerId = id, Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = vpnIp, Status = status, CreatedAtUtc = DateTimeOffset.UtcNow, UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static ProtectedResource MakeResource(string id, string destination, int port) => new()
    {
        ResourceId = id, Name = "test", Destination = destination, Protocol = Protocol.Tcp, Port = port,
        Enabled = true, CreatedAtUtc = DateTimeOffset.UtcNow, UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private static AccessPolicy MakePolicy(string ruleId, string peerId, string resourceId) => new()
    {
        RuleId = ruleId, PeerId = peerId, ResourceId = resourceId, Enabled = true,
        CreatedAtUtc = DateTimeOffset.UtcNow, UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-fwapply-{Guid.NewGuid():N}.conf");
        _tempPaths.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var p in _tempPaths)
        {
            foreach (var suffix in new[] { "", ".candidate", ".lastknowngood" })
            {
                try { if (File.Exists(p + suffix)) File.Delete(p + suffix); } catch { /* best-effort */ }
            }
        }
    }
}
