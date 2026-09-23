using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Routing;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;
using Xunit;

namespace SecureTunnel.GatewayAgent.IntegrationTests;

/// <summary>
/// CLI-level tests for `config status|list|show|diff|validate|apply|verify|rollback` (Phase 5).
/// Same approach as the other *CliInvocationTests: real command tree, mocked
/// ISystemCommandExecutor, real temp-file persistence.
/// </summary>
[Collection(ConsoleRedirectionCollection.Name)]
public sealed class ConfigLifecycleCliInvocationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalErr;

    public ConfigLifecycleCliInvocationTests()
    {
        _originalOut = Console.Out;
        _originalErr = Console.Error;
        Console.SetOut(_stdout);
        Console.SetError(_stderr);
    }

    [Fact]
    public async Task ConfigApply_WithoutConfirmation_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "config", "apply", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task ConfigApply_DryRun_DoesNotPersistOrTouchSystem()
    {
        var (root, configPath) = BuildRootWithConfig(out var mock);

        var exitCode = await root.Parse(new[] { "config", "apply", "--config", configPath, "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Empty(mock.Invocations);
    }

    [Fact]
    public async Task ConfigApply_WithYes_ReachesActive_ThenConfigStatusReflectsIt()
    {
        var (root, configPath) = BuildRootWithConfig();

        var applyExit = await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, applyExit);

        _stdout.GetStringBuilder().Clear();
        var statusExit = await root.Parse(new[] { "config", "status", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, statusExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, doc.RootElement.GetProperty("ActiveVersion").GetInt32());
    }

    [Fact]
    public async Task ConfigValidate_InvalidConfiguration_ReturnsValidationFailure()
    {
        var (root, configPath) = BuildRootWithConfig(failClosed: false);

        var exitCode = await root.Parse(new[] { "config", "validate", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task ConfigList_AfterTwoApplies_ShowsBothVersions()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        var exitCode = await root.Parse(new[] { "config", "list", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(2, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task ConfigRollback_WithoutConfirmation_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        var exitCode = await root.Parse(new[] { "config", "rollback", "--config", configPath, "--version", "1" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task ConfigRollback_ToValidVersion_Succeeds()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        var exitCode = await root.Parse(new[] { "config", "rollback", "--config", configPath, "--version", "1", "--yes", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal("RollbackSucceeded", doc.RootElement.GetProperty("State").GetString());
    }

    [Fact]
    public async Task ConfigVerify_AllUp_ReturnsSuccess()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "config", "verify", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
    }

    [Fact]
    public async Task ConfigDiff_BetweenTwoVersions_ReportsCounts()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        // Add a peer between v1 and v2 so the diff is non-trivial.
        await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1), "--yes" }).InvokeAsync();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        var exitCode = await root.Parse(new[] { "config", "diff", "--config", configPath, "--from", "1", "--to", "2", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, doc.RootElement.GetProperty("peersAdded").GetArrayLength());
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig(bool failClosed = true) => BuildRootWithConfig(out _, failClosed);

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig(out MockSystemCommandExecutor mock, bool failClosed = true)
    {
        var configPath = WriteConfig(failClosed);
        var mockExecutor = new MockSystemCommandExecutor();
        mock = mockExecutor;
        mockExecutor.Handlers["wg"] = req =>
        {
            if (req.Arguments.Contains("--version")) return MockSystemCommandExecutor.Success("wg 1.0.0");
            if (req.Arguments.Contains("show")) return MockSystemCommandExecutor.Success("interface: wg-securetunnel\n");
            return MockSystemCommandExecutor.Success();
        };
        mockExecutor.Handlers["wg-quick"] = _ => MockSystemCommandExecutor.Success();
        mockExecutor.Handlers["nft"] = req =>
        {
            if (req.Arguments.Contains("-c")) return MockSystemCommandExecutor.Success();
            if (req.Arguments.Count > 0 && req.Arguments[0] == "-f") return MockSystemCommandExecutor.Success();
            if (req.Arguments.Contains("list")) return MockSystemCommandExecutor.Success("table inet securetunnel { }");
            return MockSystemCommandExecutor.Success();
        };

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));

        services.AddScoped<IDryRunContext, DryRunContext>();
        services.AddScoped<ISystemCommandExecutor>(sp =>
        {
            var ctx = sp.GetRequiredService<IDryRunContext>();
            return ctx.IsDryRun
                ? new DryRunSystemCommandExecutor(mockExecutor, NullLogger<DryRunSystemCommandExecutor>.Instance)
                : mockExecutor;
        });

        services.AddScoped<IConfigurationLoader, YamlConfigurationLoader>();
        services.AddScoped<IConfigurationValidator, GatewayConfigurationValidator>();
        services.AddScoped<IKeyManagementService, KeyManagementService>();
        services.AddScoped<IWireGuardConfigGenerator, WireGuardConfigGenerator>();
        services.AddScoped<IWireGuardService, WireGuardService>();
        services.AddScoped<IForwardingService, ForwardingService>();
        services.AddScoped<IEnvironmentChecker>(_ => new FakeEnvironmentChecker(Array.Empty<Models.EnvironmentCheckResult>()));
        services.AddScoped<IHealthCheckService, HealthCheckService>();
        services.AddScoped<IPeerRepository, JsonFilePeerRepository>();
        services.AddScoped<IVpnIpAllocator, Ipv4VpnIpAllocator>();
        services.AddScoped<IPeerService, PeerService>();
        services.AddScoped<IClientConfigTemplateGenerator, ClientConfigTemplateGenerator>();
        services.AddScoped<IResourceRepository, JsonFileResourceRepository>();
        services.AddScoped<IResourceService, ResourceService>();
        services.AddScoped<IPolicyRepository, JsonFilePolicyRepository>();
        services.AddScoped<IPolicyService, PolicyService>();
        services.AddScoped<IFirewallRuleGenerator, FirewallRuleGenerator>();
        services.AddScoped<IFirewallService, FirewallService>();
        services.AddScoped<IFirewallApplyOrchestrator, FirewallApplyOrchestrator>();
        services.AddScoped<IConfigurationHistoryRepository, JsonFileConfigurationHistoryRepository>();
        services.AddScoped<IOperationLockFactory, FileOperationLockFactory>();
        services.AddScoped<IConfigurationLifecycleService, ConfigurationLifecycleService>();

        var provider = services.BuildServiceProvider();
        return (RootCommandFactory.Build(provider), configPath);
    }

    private string WriteConfig(bool failClosed)
    {
        string PathFor(string name) => Path.Combine(Path.GetTempPath(), $"securetunnel-cfgcli-{name}-{Guid.NewGuid():N}").Replace("\\", "/");

        var privateKeyPath = PathFor("key") + ".key";
        File.WriteAllText(privateKeyPath, "FAKE_TEST_SERVER_PRIVATE_KEY=");
        _tempFiles.Add(privateKeyPath);

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

        var yaml = $"""
            gatewayId: "gw-cfg-cli-test"
            wireGuard:
              interfaceName: "wg-securetunnel"
              listenPort: 51820
              privateKeyPath: "{privateKeyPath}"
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
              failClosed: {(failClosed ? "true" : "false")}
            peerStorePath: "{peerStorePath}"
            resourceStorePath: "{resourceStorePath}"
            policyStorePath: "{policyStorePath}"
            firewallRulesetPath: "{firewallRulesetPath}"
            configurationHistoryPath: "{historyPath}"
            operationLockPath: "{lockPath}"
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-cfgcli-config-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        Console.SetOut(_originalOut);
        Console.SetError(_originalErr);
        foreach (var f in _tempFiles)
        {
            foreach (var suffix in new[] { "", ".candidate", ".lastknowngood" })
            {
                try { if (File.Exists(f + suffix)) File.Delete(f + suffix); } catch { /* best-effort */ }
            }
        }
    }
}
