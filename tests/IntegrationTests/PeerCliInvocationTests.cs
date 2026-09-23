using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
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
/// CLI-level tests for `securetunnel-gateway peer *` (Phase 3). Mirrors
/// CliInvocationTests's approach: real command tree, mocked ISystemCommandExecutor, real
/// (temp-file) peer persistence so Add -> effective config integration is exercised end
/// to end without touching any real wg/nft process.
/// </summary>
[Collection(ConsoleRedirectionCollection.Name)]
public sealed class PeerCliInvocationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalErr;

    public PeerCliInvocationTests()
    {
        _originalOut = Console.Out;
        _originalErr = Console.Error;
        Console.SetOut(_stdout);
        Console.SetError(_stderr);
    }

    [Fact]
    public async Task PeerList_Empty_Succeeds()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "list", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("No peers registered", _stdout.ToString());
    }

    [Fact]
    public async Task PeerAdd_WithoutYesOrDryRun_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1) }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
        Assert.Contains("grants VPN access", _stderr.ToString());
    }

    [Fact]
    public async Task PeerAdd_DryRun_DoesNotPersist()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1), "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("DRY-RUN", _stdout.ToString());

        var listExit = await root.Parse(new[] { "peer", "list", "--config", configPath }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, listExit);
        Assert.Contains("No peers registered", _stdout.ToString());
    }

    [Fact]
    public async Task PeerAdd_WithYes_PersistsAndAppearsInList()
    {
        var (root, configPath) = BuildRootWithConfig();

        var addExit = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1), "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, addExit);

        _stdout.GetStringBuilder().Clear();
        var listExit = await root.Parse(new[] { "peer", "list", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, listExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal(1, doc.RootElement.GetArrayLength());
        Assert.Equal("Alice", doc.RootElement[0].GetProperty("Name").GetString());
    }

    [Fact]
    public async Task PeerAdd_InvalidPublicKey_ReturnsValidationFailureExitCode()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", "not-a-key", "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task PeerAdd_Json_OutputNeverContainsWordPrivateKey()
    {
        var (root, configPath) = BuildRootWithConfig();

        await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1), "--yes", "--json" }).InvokeAsync();

        Assert.DoesNotContain("PrivateKey", _stdout.ToString(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task PeerDisable_WithoutConfirmation_Refuses()
    {
        var (root, configPath) = BuildRootWithConfig();
        var peerId = await AddPeerAsync(root, configPath);

        var exitCode = await root.Parse(new[] { "peer", "disable", "--config", configPath, "--id", peerId }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task PeerDisable_ThenConfigGenerate_ExcludesDisabledPeer()
    {
        var (root, configPath) = BuildRootWithConfig();
        var peerId = await AddPeerAsync(root, configPath);

        var disableExit = await root.Parse(new[] { "peer", "disable", "--config", configPath, "--id", peerId, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, disableExit);

        _stdout.GetStringBuilder().Clear();
        var genExit = await root.Parse(new[] { "config", "generate", "--config", configPath, "--dry-run", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, genExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var rendered = doc.RootElement.GetProperty("rendered").GetString();
        Assert.DoesNotContain("[Peer]", rendered);
    }

    [Fact]
    public async Task PeerAdd_ThenConfigGenerate_IncludesActivePeer()
    {
        var (root, configPath) = BuildRootWithConfig();
        await AddPeerAsync(root, configPath);

        _stdout.GetStringBuilder().Clear();
        var genExit = await root.Parse(new[] { "config", "generate", "--config", configPath, "--dry-run", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, genExit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var rendered = doc.RootElement.GetProperty("rendered").GetString();
        Assert.Contains("[Peer]", rendered);
    }

    [Fact]
    public async Task PeerRevoke_ThenEnable_Fails()
    {
        var (root, configPath) = BuildRootWithConfig();
        var peerId = await AddPeerAsync(root, configPath);

        var revokeExit = await root.Parse(new[] { "peer", "revoke", "--config", configPath, "--id", peerId, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, revokeExit);

        var enableExit = await root.Parse(new[] { "peer", "enable", "--config", configPath, "--id", peerId, "--yes" }).InvokeAsync();
        Assert.Equal(ExitCodes.GeneralFailure, enableExit);
    }

    [Fact]
    public async Task PeerShow_UnknownId_ReturnsFailure()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "show", "--config", configPath, "--id", "peer-does-not-exist" }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
    }

    [Fact]
    public async Task PeerAllocateIp_PreviewsWithoutPersisting()
    {
        var (root, configPath) = BuildRootWithConfig();

        var exitCode = await root.Parse(new[] { "peer", "allocate-ip", "--config", configPath, "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.Equal("10.250.0.10", doc.RootElement.GetProperty("AllocatedIp").GetString());

        _stdout.GetStringBuilder().Clear();
        var listExit = await root.Parse(new[] { "peer", "list", "--config", configPath }).InvokeAsync();
        Assert.Contains("No peers registered", _stdout.ToString());
    }

    private async Task<string> AddPeerAsync(RootCommand root, string configPath)
    {
        _stdout.GetStringBuilder().Clear();
        var exit = await root.Parse(new[] { "peer", "add", "--config", configPath, "--name", "Alice", "--public-key", ValidKey(1), "--yes", "--json" }).InvokeAsync();
        Assert.Equal(ExitCodes.Success, exit);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        var peerId = doc.RootElement.GetProperty("peer").GetProperty("PeerId").GetString()!;
        _stdout.GetStringBuilder().Clear();
        return peerId;
    }

    private static string ValidKey(int seed)
    {
        var bytes = new byte[32];
        new Random(seed).NextBytes(bytes);
        return Convert.ToBase64String(bytes);
    }

    private (RootCommand Root, string ConfigPath) BuildRootWithConfig()
    {
        var configPath = WriteConfig();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));

        var mockExecutor = new MockSystemCommandExecutor();
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

        var provider = services.BuildServiceProvider();
        return (RootCommandFactory.Build(provider), configPath);
    }

    private string WriteConfig()
    {
        var peerStorePath = Path.Combine(Path.GetTempPath(), $"securetunnel-clipeers-{Guid.NewGuid():N}.json").Replace("\\", "/");
        var yaml = $"""
            gatewayId: "gw-cli-peer-test"
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
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-clipeer-config-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        _tempFiles.Add(peerStorePath);
        return path;
    }

    public void Dispose()
    {
        Console.SetOut(_originalOut);
        Console.SetError(_originalErr);
        foreach (var f in _tempFiles)
        {
            try { if (File.Exists(f)) File.Delete(f); } catch { /* best-effort */ }
        }
    }
}
