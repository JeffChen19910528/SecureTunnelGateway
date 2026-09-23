using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Backup;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Daemon;
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
/// CLI-level tests for `gateway status|backup|backup list|restore` (Phase 6).
/// Same approach as the other *CliInvocationTests: real command tree, mocked
/// ISystemCommandExecutor, real temp-file persistence.
/// </summary>
[Collection(ConsoleRedirectionCollection.Name)]
public sealed class GatewayCliInvocationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly List<string> _tempDirs = new();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalErr;

    public GatewayCliInvocationTests()
    {
        _originalOut = Console.Out;
        _originalErr = Console.Error;
        Console.SetOut(_stdout);
        Console.SetError(_stderr);
    }

    [Fact]
    public async Task GatewayStatus_FreshConfig_ReportsDesiredStale()
    {
        // Note: this asserts only on `desiredStale`, not the exit code/overallStatus -
        // IKeyManagementService.CheckPrivateKeyPermissions deliberately fails closed on
        // Windows (it cannot verify Unix file modes there), so `health` is always
        // "Unhealthy" and the exit code always GeneralFailure when this suite runs on the
        // Windows/WSL2 dev host, independent of the staleness signal under test here.
        var (root, configPath) = BuildRootWithConfig();

        await root.Parse(new[] { "gateway", "status", "--config", configPath, "--json" }).InvokeAsync();

        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.True(doc.RootElement.GetProperty("desiredStale").GetBoolean());
    }

    [Fact]
    public async Task GatewayStatus_AfterApply_ReportsNotStale()
    {
        // See GatewayStatus_FreshConfig_ReportsDesiredStale for why overallStatus/exit code
        // are not asserted here.
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        await root.Parse(new[] { "gateway", "status", "--config", configPath, "--json" }).InvokeAsync();

        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.False(doc.RootElement.GetProperty("desiredStale").GetBoolean());
        Assert.Equal(1, doc.RootElement.GetProperty("activeVersion").GetInt32());
    }

    [Fact]
    public async Task GatewayStatus_InvalidConfigPath_ReturnsFailure()
    {
        var (root, _) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "gateway", "status", "--config", NonExistentPath(), "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal("Failed", doc.RootElement.GetProperty("overallStatus").GetString());
    }

    [Fact]
    public async Task GatewayBackupCreate_ThenList_ShowsTheBackup()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        var createExit = await root.Parse(new[] { "gateway", "backup", "create", "--config", configPath, "--json" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, createExit);
        using (var createDoc = System.Text.Json.JsonDocument.Parse(_stdout.ToString()))
        {
            Assert.True(createDoc.RootElement.GetProperty("Success").GetBoolean());
        }

        _stdout.GetStringBuilder().Clear();
        var listExit = await root.Parse(new[] { "gateway", "backup", "list", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, listExit);
        using var listDoc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, listDoc.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task GatewayBackup_NoSubcommand_BehavesLikeCreate()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        var exitCode = await root.Parse(new[] { "gateway", "backup", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.True(doc.RootElement.GetProperty("Success").GetBoolean());
    }

    [Fact]
    public async Task GatewayBackupCreate_DryRun_DoesNotWriteArchive()
    {
        var (root, configPath) = BuildRootWithConfig(out _, out var backupDir);
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        var exitCode = await root.Parse(new[] { "gateway", "backup", "create", "--config", configPath, "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.False(Directory.Exists(backupDir) && Directory.GetFiles(backupDir).Length > 0);
    }

    [Fact]
    public async Task GatewayRestore_WithoutConfirmation_Refuses()
    {
        var (root, configPath, archivePath) = await BuildRootWithBackupAsync();

        var exitCode = await root.Parse(new[] { "gateway", "restore", "--config", configPath, "--file", archivePath }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task GatewayRestore_DryRun_TouchesNothing()
    {
        var (root, configPath, archivePath) = await BuildRootWithBackupAsync();

        var exitCode = await root.Parse(new[] { "gateway", "restore", "--config", configPath, "--file", archivePath, "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
    }

    [Fact]
    public async Task GatewayRestore_WithYes_Succeeds_AndDoesNotAutoApply()
    {
        // `gateway status`'s exit code/overallStatus is not asserted here - see
        // GatewayStatus_FreshConfig_ReportsDesiredStale for why (Windows-only health
        // limitation unrelated to what this test is verifying: that restore never
        // auto-applies).
        var (root, configPath, archivePath) = await BuildRootWithBackupAsync();

        _stdout.GetStringBuilder().Clear();
        var exitCode = await root.Parse(new[] { "gateway", "restore", "--config", configPath, "--file", archivePath, "--yes", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.True(doc.RootElement.GetProperty("Success").GetBoolean());

        // Restore never runs `config apply` itself, so the Active version must be
        // unchanged by it (proving "does not auto-apply", independent of the Windows-only
        // health-status caveat noted above).
        _stdout.GetStringBuilder().Clear();
        await root.Parse(new[] { "gateway", "status", "--config", configPath, "--json" }).InvokeAsync();
        using var statusDoc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, statusDoc.RootElement.GetProperty("activeVersion").GetInt32());
    }

    [Fact]
    public async Task GatewayServe_Once_InvalidConfigPath_ReturnsValidationFailure()
    {
        var (root, _) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "gateway", "serve", "--config", NonExistentPath(), "--once" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task GatewayServe_Once_ValidConfig_DoesNotHang_ReturnsWithoutEnteringLoop()
    {
        // `--once` runs startup diagnostics and exits instead of entering the persistent
        // loop - this is the CLI-level smoke test that the `serve` command is wired up
        // correctly end to end; GatewayDaemonServiceTests (tests/DaemonTests) covers the
        // full startup-classification/loop/cancellation behavior in isolation.
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "gateway", "serve", "--config", configPath, "--once" }).InvokeAsync();

        // Success or GeneralFailure are both valid depending on this host's health-check
        // outcome (see the Windows key-permission caveat noted elsewhere in this file) -
        // what matters is that it returned promptly rather than blocking on the run loop.
        Assert.True(exitCode is ExitCodes.Success or ExitCodes.GeneralFailure);
    }

    [Fact]
    public async Task GatewayRestore_MissingArchive_ReturnsFailure()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "gateway", "restore", "--config", configPath, "--file", NonExistentPath(), "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    private async Task<(RootCommand Root, string ConfigPath, string ArchivePath)> BuildRootWithBackupAsync()
    {
        var (root, configPath) = BuildRootWithConfig();
        await root.Parse(new[] { "config", "apply", "--config", configPath, "--yes" }).InvokeAsync();

        _stdout.GetStringBuilder().Clear();
        await root.Parse(new[] { "gateway", "backup", "create", "--config", configPath, "--json" }).InvokeAsync();
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var archivePath = doc.RootElement.GetProperty("ArchivePath").GetString()!;
        _stdout.GetStringBuilder().Clear();

        return (root, configPath, archivePath);
    }

    private static string NonExistentPath() =>
        Path.Combine(Path.GetTempPath(), $"securetunnel-gwcli-missing-{Guid.NewGuid():N}");

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig() => BuildRootWithConfig(out _, out _);

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig(out MockSystemCommandExecutor mock, out string backupDir)
    {
        var configPath = WriteConfig(out var backupDirLocal);
        backupDir = backupDirLocal;
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
        services.AddScoped<IBackupService, BackupService>();
        services.AddScoped<IDaemonTicker, SystemDaemonTicker>();
        services.AddScoped<IGatewayDaemonService, GatewayDaemonService>();

        var provider = services.BuildServiceProvider();
        return (RootCommandFactory.Build(provider), configPath);
    }

    private string WriteConfig(out string backupDir)
    {
        string PathFor(string name) => Path.Combine(Path.GetTempPath(), $"securetunnel-gwcli-{name}-{Guid.NewGuid():N}").Replace("\\", "/");

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
        backupDir = Path.Combine(Path.GetTempPath(), $"securetunnel-gwcli-backupdir-{Guid.NewGuid():N}").Replace("\\", "/");
        _tempDirs.Add(backupDir);

        foreach (var p in new[] { wgOutputPath, peerStorePath, resourceStorePath, policyStorePath, firewallRulesetPath, historyPath, lockPath })
        {
            _tempFiles.Add(p);
        }

        var yaml = $"""
            gatewayId: "gw-cli-test"
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
              failClosed: true
            peerStorePath: "{peerStorePath}"
            resourceStorePath: "{resourceStorePath}"
            policyStorePath: "{policyStorePath}"
            firewallRulesetPath: "{firewallRulesetPath}"
            configurationHistoryPath: "{historyPath}"
            operationLockPath: "{lockPath}"
            backupDirectory: "{backupDir}"
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-gwcli-config-{Guid.NewGuid():N}.yaml");
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
        foreach (var d in _tempDirs)
        {
            try { if (Directory.Exists(d)) Directory.Delete(d, recursive: true); } catch { /* best-effort */ }
        }
    }
}
