using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Health;
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
/// CLI-level tests for `resource`, `policy`, and `firewall` (Phase 4). Same approach as
/// CliInvocationTests/PeerCliInvocationTests: real command tree, mocked
/// ISystemCommandExecutor, real temp-file persistence.
/// </summary>
[Collection(ConsoleRedirectionCollection.Name)]
public sealed class FirewallCliInvocationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalErr;

    public FirewallCliInvocationTests()
    {
        _originalOut = Console.Out;
        _originalErr = Console.Error;
        Console.SetOut(_stdout);
        Console.SetError(_stderr);
    }

    [Fact]
    public async Task ResourceAdd_WithYes_AppearsInList()
    {
        var (root, configPath) = BuildRootWithConfig();

        var addExit = await root.Parse(new[] { "resource", "add", "--config", configPath, "--name", "Website", "--destination", "10.20.0.10", "--protocol", "tcp", "--port", "443", "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, addExit);

        _stdout.GetStringBuilder().Clear();
        var listExit = await root.Parse(new[] { "resource", "list", "--config", configPath, "--json" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, listExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, doc.RootElement.GetArrayLength());
    }

    [Fact]
    public async Task ResourceAdd_WithoutConfirmation_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "resource", "add", "--config", configPath, "--name", "Website", "--destination", "10.20.0.10", "--protocol", "tcp", "--port", "443" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task ResourceAdd_InvalidProtocol_ReturnsValidationFailure()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "resource", "add", "--config", configPath, "--name", "Website", "--destination", "10.20.0.10", "--protocol", "icmp", "--port", "443", "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task ResourceAdd_UnrestrictedDestination_ReturnsValidationFailure()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "resource", "add", "--config", configPath, "--name", "Everything", "--destination", "0.0.0.0/0", "--protocol", "tcp", "--port", "443", "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task PolicyAdd_UnknownPeer_ReturnsValidationFailure()
    {
        var (root, configPath) = BuildRootWithConfig();
        var resourceId = await AddResourceAsync(root, configPath);

        var exitCode = await root.Parse(new[] { "policy", "add", "--config", configPath, "--peer-id", "peer-does-not-exist", "--resource-id", resourceId, "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task FullFlow_AddPeerResourcePolicy_FirewallGenerateIncludesRule()
    {
        var (root, configPath) = BuildRootWithConfig();
        var peerId = await AddPeerAsync(root, configPath);
        var resourceId = await AddResourceAsync(root, configPath);

        var policyExit = await root.Parse(new[] { "policy", "add", "--config", configPath, "--peer-id", peerId, "--resource-id", resourceId, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, policyExit);

        _stdout.GetStringBuilder().Clear();
        var genExit = await root.Parse(new[] { "firewall", "generate", "--config", configPath, "--dry-run", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, genExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, doc.RootElement.GetProperty("effectiveRuleCount").GetInt32());
        Assert.Contains("10.20.0.10", doc.RootElement.GetProperty("rendered").GetString());
    }

    [Fact]
    public async Task FullFlow_DisableResource_ExcludedFromFirewallGenerate()
    {
        var (root, configPath) = BuildRootWithConfig();
        var peerId = await AddPeerAsync(root, configPath);
        var resourceId = await AddResourceAsync(root, configPath);
        await root.Parse(new[] { "policy", "add", "--config", configPath, "--peer-id", peerId, "--resource-id", resourceId, "--yes" }).InvokeAsync();

        var disableExit = await root.Parse(new[] { "resource", "disable", "--config", configPath, "--id", resourceId, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, disableExit);

        _stdout.GetStringBuilder().Clear();
        var genExit = await root.Parse(new[] { "firewall", "generate", "--config", configPath, "--dry-run", "--json" }).InvokeAsync();
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());

        Assert.Equal(ExitCodes.Success, genExit);
        Assert.Equal(0, doc.RootElement.GetProperty("effectiveRuleCount").GetInt32());
    }

    [Fact]
    public async Task FirewallValidate_EmptyEverything_Succeeds()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "firewall", "validate", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("VALID", _stdout.ToString());
    }

    [Fact]
    public async Task FirewallApply_WithoutConfirmation_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "firewall", "apply", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task FirewallApply_DryRun_NeverCallsNft()
    {
        var (root, configPath) = BuildRootWithConfig(out var mock);

        var exitCode = await root.Parse(new[] { "firewall", "apply", "--config", configPath, "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Empty(mock.Invocations);
    }

    [Fact]
    public async Task FirewallStatus_NftNotInstalled_ReportsBlockedNotSuccess()
    {
        var (root, _) = BuildRootWithConfig(out var mock);
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("not found");

        // `firewall status`/`show` target the fixed "inet securetunnel" table name and
        // take no --config (there is nothing config-dependent about which table to query).
        var exitCode = await root.Parse(new[] { "firewall", "status" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
        Assert.Contains("BLOCKED", _stdout.ToString());
    }

    private async Task<string> AddPeerAsync(RootCommand root, string configPath)
    {
        _stdout.GetStringBuilder().Clear();
        var exit = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(Random.Shared.Next()), "--yes", "--json" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, exit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var id = doc.RootElement.GetProperty("peer").GetProperty("PeerId").GetString()!;
        _stdout.GetStringBuilder().Clear();
        return id;
    }

    private async Task<string> AddResourceAsync(RootCommand root, string configPath)
    {
        _stdout.GetStringBuilder().Clear();
        var exit = await root.Parse(new[] { "resource", "add", "--config", configPath, "--name", "Website", "--destination", "10.20.0.10", "--protocol", "tcp", "--port", "443", "--yes", "--json" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, exit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var id = doc.RootElement.GetProperty("resource").GetProperty("ResourceId").GetString()!;
        _stdout.GetStringBuilder().Clear();
        return id;
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig() => BuildRootWithConfig(out _);

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig(out MockSystemCommandExecutor mock)
    {
        var configPath = WriteConfig();
        var mockExecutor = new MockSystemCommandExecutor();
        mock = mockExecutor;

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

        var provider = services.BuildServiceProvider();
        return (RootCommandFactory.Build(provider), configPath);
    }

    private string WriteConfig()
    {
        string PathFor(string name) => Path.Combine(Path.GetTempPath(), $"securetunnel-fwcli-{name}-{Guid.NewGuid():N}").Replace("\\", "/");

        var peerStorePath = PathFor("peers") + ".json";
        var resourceStorePath = PathFor("resources") + ".json";
        var policyStorePath = PathFor("policies") + ".json";
        var firewallRulesetPath = PathFor("ruleset") + ".conf";

        var yaml = $"""
            gatewayId: "gw-fw-cli-test"
            wireGuard:
              interfaceName: "wg-securetunnel"
              listenPort: 51820
              privateKeyPath: "/etc/securetunnel-gateway/keys/server.key"
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
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-fwcli-config-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        _tempFiles.Add(peerStorePath);
        _tempFiles.Add(resourceStorePath);
        _tempFiles.Add(policyStorePath);
        _tempFiles.Add(firewallRulesetPath);
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
