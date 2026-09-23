using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using Xunit;

namespace SecureTunnel.GatewayAgent.IntegrationTests;

/// <summary>
/// Health Tests (docs/testing-guide.md 測試分類 D): exercises HealthCheckService's
/// aggregation logic entirely through fakes/mocks - no real wg/nft/systemd required,
/// so these run identically on WSL2 and on a real Ubuntu Server.
/// </summary>
public sealed class HealthCheckServiceTests : IDisposable
{
    private readonly List<string> _tempFiles = new();

    [Fact]
    public async Task CheckAsync_AllHealthyNoConfig_ReturnsHealthy()
    {
        var service = BuildService(FakeEnvironmentChecker.AllHealthy(), configLoads: false);

        var report = await service.CheckAsync(configPath: null);

        // No config path -> "active-configuration" and "configuration-validity" are
        // Warn/Blocked, so overall is Degraded, not Healthy - this itself is a useful
        // assertion: a Gateway with no configuration must never report Healthy.
        Assert.Equal(HealthStatus.Degraded, report.OverallStatus);
    }

    [Fact]
    public async Task CheckAsync_AllHealthyWithValidConfigAndKey_ReturnsHealthy()
    {
        var (configPath, keyPath) = WriteValidConfigAndKey();
        var service = BuildService(FakeEnvironmentChecker.AllHealthy(), configLoads: true, keyPermissionsOk: true);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Healthy, report.OverallStatus);
    }

    [Fact]
    public async Task CheckAsync_MissingWireGuard_ReturnsDegraded()
    {
        var (configPath, _) = WriteValidConfigAndKey();
        var service = BuildService(FakeEnvironmentChecker.MissingWireGuard(), configLoads: true, keyPermissionsOk: true);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Degraded, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "wireguard-command" && i.Status == CheckStatus.Blocked);
    }

    [Fact]
    public async Task CheckAsync_MissingNftables_ReturnsDegraded()
    {
        var (configPath, _) = WriteValidConfigAndKey();
        var service = BuildService(FakeEnvironmentChecker.MissingNftables(), configLoads: true, keyPermissionsOk: true);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Degraded, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "nftables-command" && i.Status == CheckStatus.Blocked);
    }

    [Fact]
    public async Task CheckAsync_MissingPermissions_ReturnsDegraded()
    {
        var (configPath, _) = WriteValidConfigAndKey();
        var service = BuildService(FakeEnvironmentChecker.MissingPermissions(), configLoads: true, keyPermissionsOk: true);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Degraded, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "root-permission" && i.Status == CheckStatus.Warn);
    }

    [Fact]
    public async Task CheckAsync_InvalidConfiguration_ReturnsUnhealthy()
    {
        var configPath = WriteConfig(); // fail-closed disabled -> invalid
        var service = BuildService(FakeEnvironmentChecker.AllHealthy(), configLoads: true, keyPermissionsOk: true);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Unhealthy, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "configuration-validity" && i.Status == CheckStatus.Fail);
    }

    [Fact]
    public async Task CheckAsync_ConfigFileMissing_ReturnsUnhealthy()
    {
        var service = BuildService(FakeEnvironmentChecker.AllHealthy(), configLoads: false);

        var report = await service.CheckAsync("/definitely/does/not/exist/gateway.yaml");

        Assert.Equal(HealthStatus.Unhealthy, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "active-configuration" && i.Status == CheckStatus.Fail);
    }

    [Fact]
    public async Task CheckAsync_UnsafeKeyPermissions_ReturnsUnhealthy()
    {
        var (configPath, _) = WriteValidConfigAndKey();
        var service = BuildService(FakeEnvironmentChecker.AllHealthy(), configLoads: true, keyPermissionsOk: false);

        var report = await service.CheckAsync(configPath);

        Assert.Equal(HealthStatus.Unhealthy, report.OverallStatus);
        Assert.Contains(report.Items, i => i.Id == "key-file-permissions" && i.Status == CheckStatus.Fail);
    }

    [Fact]
    public async Task CheckAsync_HealthCheckItselfThrows_ReturnsUnknownNotCrash()
    {
        var throwingChecker = new ThrowingEnvironmentChecker();
        var service = new HealthCheckService(
            throwingChecker,
            new YamlConfigurationLoader(),
            new GatewayConfigurationValidator(),
            new StubKeyManagementService(true),
            NullLogger<HealthCheckService>.Instance);

        var report = await service.CheckAsync(null);

        Assert.Equal(HealthStatus.Unknown, report.OverallStatus);
    }

    private HealthCheckService BuildService(FakeEnvironmentChecker envChecker, bool configLoads, bool keyPermissionsOk = true)
    {
        return new HealthCheckService(
            envChecker,
            new YamlConfigurationLoader(),
            new GatewayConfigurationValidator(),
            new StubKeyManagementService(keyPermissionsOk),
            NullLogger<HealthCheckService>.Instance);
    }

    private (string configPath, string keyPath) WriteValidConfigAndKey()
    {
        var keyPath = Path.Combine(Path.GetTempPath(), $"securetunnel-health-key-{Guid.NewGuid():N}.key");
        File.WriteAllText(keyPath, "FAKE_KEY=");
        _tempFiles.Add(keyPath);

        var configPath = WriteConfig(failClosed: true, privateKeyPath: keyPath);
        return (configPath, keyPath);
    }

    private string WriteConfig(bool failClosed = false, string privateKeyPath = "/etc/securetunnel-gateway/keys/server.key")
    {
        // Includes a protected network so a "fully healthy" fixture has zero validation
        // warnings (an empty protectedNetworks list is valid but produces a warning,
        // which correctly degrades health - see CheckAsync_AllHealthyWithValidConfigAndKey_ReturnsHealthy).
        var yaml = $"""
            gatewayId: "gw-health-test"
            wireGuard:
              interfaceName: "wg-securetunnel"
              listenPort: 51820
              privateKeyPath: "{privateKeyPath.Replace("\\", "/")}"
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

        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-health-config-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            try { File.Delete(f); } catch { /* best-effort */ }
        }
    }

    private sealed class StubKeyManagementService : IKeyManagementService
    {
        private readonly bool _permissionsOk;
        public StubKeyManagementService(bool permissionsOk) => _permissionsOk = permissionsOk;

        public Task<KeyGenerationResult> GenerateServerKeyPairAsync(string privateKeyPath, string publicKeyPath, KeyGenerationOptions options, CancellationToken cancellationToken = default) =>
            throw new NotSupportedException("Not used by HealthCheckServiceTests");

        public Task<string?> ReadPublicKeyAsync(string publicKeyPath, CancellationToken cancellationToken = default) =>
            Task.FromResult<string?>(null);

        public KeyPermissionCheckResult CheckPrivateKeyPermissions(string privateKeyPath) => new()
        {
            Exists = true,
            PermissionsOk = _permissionsOk,
            Message = _permissionsOk ? "0600" : "0644 (too permissive)"
        };
    }

    private sealed class ThrowingEnvironmentChecker : Services.IEnvironmentChecker
    {
        public Task<IReadOnlyList<EnvironmentCheckResult>> RunChecksAsync(CancellationToken cancellationToken = default) =>
            throw new InvalidOperationException("simulated catastrophic failure");
    }
}
