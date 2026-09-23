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
/// Integration Tests (docs/testing-guide.md 測試分類 E): invokes the real CLI command
/// tree end-to-end, but with ISystemCommandExecutor swapped for a
/// <see cref="MockSystemCommandExecutor"/> so nothing touches a real wg/nft/systemd
/// process. Verifies exit codes and both output formats.
/// </summary>
[Collection(ConsoleRedirectionCollection.Name)]
public sealed class CliInvocationTests : IDisposable
{
    private readonly List<string> _tempFiles = new();
    private readonly StringWriter _stdout = new();
    private readonly StringWriter _stderr = new();
    private readonly TextWriter _originalOut;
    private readonly TextWriter _originalErr;

    public CliInvocationTests()
    {
        _originalOut = Console.Out;
        _originalErr = Console.Error;
        Console.SetOut(_stdout);
        Console.SetError(_stderr);
    }

    [Fact]
    public async Task Version_ReturnsSuccessExitCode()
    {
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "version" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("SecureTunnel Gateway Agent", _stdout.ToString());
    }

    [Fact]
    public async Task Version_Json_ProducesParseableJson()
    {
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "version", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        var output = _stdout.ToString();
        using var doc = System.Text.Json.JsonDocument.Parse(output);
        Assert.True(doc.RootElement.TryGetProperty("version", out _));
    }

    [Fact]
    public async Task Validate_ValidConfig_ReturnsSuccessExitCode()
    {
        var configPath = WriteValidConfig();
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "validate", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains("VALID", _stdout.ToString());
    }

    [Fact]
    public async Task Validate_InvalidConfig_ReturnsValidationFailureExitCode()
    {
        var configPath = WriteConfig(failClosed: false);
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "validate", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task Validate_MissingConfigFile_ReturnsValidationFailureExitCode()
    {
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "validate", "--config", "/does/not/exist.yaml" }).InvokeAsync();

        Assert.Equal(ExitCodes.ValidationFailure, exitCode);
    }

    [Fact]
    public async Task WireGuardStart_WithoutYesOrDryRun_RefusesAndReturnsFailure()
    {
        var configPath = WriteValidConfig();
        var root = BuildRoot(out var mock);

        var exitCode = await root.Parse(new[] { "wireguard", "start", "--config", configPath }).InvokeAsync();

        Assert.Equal(ExitCodes.GeneralFailure, exitCode);
        Assert.Empty(mock.Invocations); // nothing was executed
    }

    [Fact]
    public async Task WireGuardStart_WithYes_InvokesMockedWgQuick()
    {
        var configPath = WriteValidConfig();
        var root = BuildRoot(out var mock);

        var exitCode = await root.Parse(new[] { "wireguard", "start", "--config", configPath, "--yes" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Contains(mock.Invocations, i => i.Command == "wg-quick" && i.Arguments.SequenceEqual(new[] { "up", "wg-securetunnel" }));
    }

    [Fact]
    public async Task WireGuardStart_DryRun_NeverReachesMockedExecutor()
    {
        var configPath = WriteValidConfig();
        var root = BuildRoot(out var mock);

        var exitCode = await root.Parse(new[] { "wireguard", "start", "--config", configPath, "--dry-run" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        Assert.Empty(mock.Invocations); // dry-run executor intercepted before the mock (real) executor
    }

    [Fact]
    public async Task ConfigGenerate_Json_ProducesParseableJsonWithExpectedFields()
    {
        var configPath = WriteValidConfig();
        var outputPath = Path.Combine(Path.GetTempPath(), $"securetunnel-cli-out-{Guid.NewGuid():N}.conf");
        _tempFiles.Add(outputPath);
        var root = BuildRoot(out _);

        var exitCode = await root.Parse(new[] { "config", "generate", "--config", configPath, "--dry-run", "--json" }).InvokeAsync();

        Assert.Equal(ExitCodes.Success, exitCode);
        using var doc = System.Text.Json.JsonDocument.Parse(_stdout.ToString());
        Assert.True(doc.RootElement.GetProperty("Success").GetBoolean());
        Assert.True(doc.RootElement.GetProperty("DryRun").GetBoolean());
        var rendered = doc.RootElement.GetProperty("rendered").GetString();
        Assert.Contains("<loaded from", rendered);
    }

    private RootCommand BuildRoot(out MockSystemCommandExecutor mock)
    {
        var mockExecutor = new MockSystemCommandExecutor();
        mock = mockExecutor;

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));

        // Mirrors Program.cs's dry-run wiring exactly, so these tests exercise the same
        // DI shape the real CLI uses - but with the mock standing in for the "real"
        // executor, so --dry-run is proven to short-circuit before anything that would
        // otherwise touch a real process.
        services.AddScoped<IDryRunContext, DryRunContext>();
        services.AddScoped<ISystemCommandExecutor>(sp =>
        {
            var dryRunContext = sp.GetRequiredService<IDryRunContext>();
            return dryRunContext.IsDryRun
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
        return RootCommandFactory.Build(provider);
    }

    private string WriteValidConfig() => WriteConfig(failClosed: true);

    private string WriteConfig(bool failClosed)
    {
        var yaml = $"""
            gatewayId: "gw-cli-test"
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
              failClosed: {(failClosed ? "true" : "false")}
            """;

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-cli-config-{Guid.NewGuid():N}.yaml");
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
            try { File.Delete(f); } catch { /* best-effort */ }
        }
    }
}
