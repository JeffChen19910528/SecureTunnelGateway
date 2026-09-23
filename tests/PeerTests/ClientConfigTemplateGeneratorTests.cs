using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.PeerTests;

public sealed class ClientConfigTemplateGeneratorTests : IDisposable
{
    private readonly List<string> _tempPaths = new();

    [Fact]
    public async Task GenerateAsync_ServerPublicKeyMissing_ReturnsBlockedFailure()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = "/definitely/does/not/exist.pub";
        var generator = new ClientConfigTemplateGenerator(new KeyManagementService(new TestSupport.MockSystemCommandExecutor(), Microsoft.Extensions.Logging.Abstractions.NullLogger<KeyManagementService>.Instance));

        var result = await generator.GenerateAsync(config, MakePeer());

        Assert.False(result.Success);
        Assert.Contains("BLOCKED", result.Message);
    }

    [Fact]
    public async Task GenerateAsync_Success_IsNeverACompleteUsableConfig()
    {
        var generator = await BuildGeneratorWithServerKeyAsync();
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = _serverPublicKeyPath!;

        var result = await generator.GenerateAsync(config, MakePeer());

        Assert.True(result.Success);
        Assert.False(result.IsCompleteUsableConfig);
        Assert.Contains("INSERT_CLIENT_PRIVATE_KEY_HERE", result.RenderedTemplate);
    }

    [Fact]
    public async Task GenerateAsync_NoEndpointConfigured_UsesPlaceholder()
    {
        var generator = await BuildGeneratorWithServerKeyAsync();
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = _serverPublicKeyPath!;
        config.WireGuard.EndpointHost = null;

        var result = await generator.GenerateAsync(config, MakePeer());

        Assert.Contains("<GATEWAY_PUBLIC_ENDPOINT>", result.RenderedTemplate);
    }

    [Fact]
    public async Task GenerateAsync_EndpointConfigured_IsUsedDirectly()
    {
        var generator = await BuildGeneratorWithServerKeyAsync();
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = _serverPublicKeyPath!;
        config.WireGuard.EndpointHost = "vpn.example.com";

        var result = await generator.GenerateAsync(config, MakePeer());

        Assert.Contains("Endpoint = vpn.example.com:51820", result.RenderedTemplate);
        Assert.DoesNotContain("<GATEWAY_PUBLIC_ENDPOINT>", result.RenderedTemplate);
    }

    [Fact]
    public async Task GenerateAsync_AllowedIps_IncludesVpnAndProtectedNetworks()
    {
        var generator = await BuildGeneratorWithServerKeyAsync();
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = _serverPublicKeyPath!;

        var result = await generator.GenerateAsync(config, MakePeer());

        Assert.Contains("AllowedIPs = 10.250.0.0/24, 10.20.0.0/24", result.RenderedTemplate);
    }

    [Fact]
    public async Task GenerateAsync_UsesPeerAssignedVpnIpAsInterfaceAddress()
    {
        var generator = await BuildGeneratorWithServerKeyAsync();
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PublicKeyPath = _serverPublicKeyPath!;

        var result = await generator.GenerateAsync(config, MakePeer(ip: "10.250.0.42"));

        Assert.Contains("Address = 10.250.0.42/32", result.RenderedTemplate);
    }

    private string? _serverPublicKeyPath;

    private async Task<ClientConfigTemplateGenerator> BuildGeneratorWithServerKeyAsync()
    {
        _serverPublicKeyPath = TempPath();
        await File.WriteAllTextAsync(_serverPublicKeyPath, "SERVER_PUBLIC_KEY_VALUE=");
        return new ClientConfigTemplateGenerator(new KeyManagementService(new MockSystemCommandExecutor(), Microsoft.Extensions.Logging.Abstractions.NullLogger<KeyManagementService>.Instance));
    }

    private static Peer MakePeer(string ip = "10.250.0.10") => new()
    {
        PeerId = "peer-test",
        Name = "test",
        PublicKey = Convert.ToBase64String(Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()),
        AssignedVpnIp = ip,
        Status = PeerStatus.Active,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-clienttmpl-{Guid.NewGuid():N}.pub");
        _tempPaths.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var p in _tempPaths)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { /* best-effort */ }
        }
    }
}
