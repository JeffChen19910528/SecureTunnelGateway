using SecureTunnel.GatewayAgent.Configuration;
using Xunit;

namespace SecureTunnel.GatewayAgent.ConfigurationTests;

public sealed class YamlConfigurationLoaderTests : IDisposable
{
    private readonly List<string> _tempFiles = new();

    [Fact]
    public void Load_ValidYaml_PopulatesAllSections()
    {
        var path = WriteTemp("""
            gatewayId: "gw-1"
            gatewayName: "My Gateway"
            wireGuard:
              interfaceName: "wg-securetunnel"
              listenPort: 51820
              address: "10.250.0.1/24"
              privateKeyPath: "/etc/securetunnel-gateway/keys/server.key"
              publicKeyPath: "/etc/securetunnel-gateway/keys/server.pub"
            network:
              vpnCidr: "10.250.0.0/24"
              gatewayVpnAddress: "10.250.0.1"
              clientAddressPoolStart: "10.250.0.10"
              clientAddressPoolEnd: "10.250.0.200"
              lanInterface: "eth0"
              protectedNetworks:
                - name: "lab"
                  cidr: "10.20.0.0/24"
            routing:
              mode: "nat"
            security:
              firewallDefaultPolicy: "deny"
              failClosed: true
            """);

        var loader = new YamlConfigurationLoader();
        var config = loader.Load(path);

        Assert.Equal("gw-1", config.GatewayId);
        Assert.Equal("wg-securetunnel", config.WireGuard.InterfaceName);
        Assert.Equal(51820, config.WireGuard.ListenPort);
        Assert.Equal("10.250.0.0/24", config.Network.VpnCidr);
        Assert.Single(config.Network.ProtectedNetworks);
        Assert.Equal("lab", config.Network.ProtectedNetworks[0].Name);
        Assert.Equal("nat", config.Routing.Mode);
    }

    [Fact]
    public void Load_MissingSections_FallsBackToModelDefaults()
    {
        // Only gatewayId is present; every other section should use the C# model's
        // own default values (see Models/*.cs), not throw or leave nulls.
        var path = WriteTemp("gatewayId: \"gw-defaults\"\n");

        var loader = new YamlConfigurationLoader();
        var config = loader.Load(path);

        Assert.Equal("gw-defaults", config.GatewayId);
        Assert.Equal("wg-securetunnel", config.WireGuard.InterfaceName); // default
        Assert.Equal(51820, config.WireGuard.ListenPort); // default
        Assert.Equal("nat", config.Routing.Mode); // default
        Assert.True(config.Security.FailClosed); // default
        Assert.Equal("deny", config.Security.FirewallDefaultPolicy); // default
        Assert.False(config.Security.AllowUnlistedResources); // default
    }

    [Fact]
    public void Load_FileDoesNotExist_ThrowsFileNotFoundException()
    {
        var loader = new YamlConfigurationLoader();
        Assert.Throws<FileNotFoundException>(() => loader.Load("/nonexistent/gateway.yaml"));
    }

    [Fact]
    public void Load_EmptyFile_Throws()
    {
        var path = WriteTemp(string.Empty);
        var loader = new YamlConfigurationLoader();
        Assert.ThrowsAny<Exception>(() => loader.Load(path));
    }

    [Fact]
    public void Load_UnknownProperty_IsIgnoredNotThrown()
    {
        var path = WriteTemp("""
            gatewayId: "gw-1"
            somethingUnrelatedFromAFutureVersion: "value"
            """);

        var loader = new YamlConfigurationLoader();
        var config = loader.Load(path);

        Assert.Equal("gw-1", config.GatewayId);
    }

    private string WriteTemp(string yaml)
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-test-{Guid.NewGuid():N}.yaml");
        File.WriteAllText(path, yaml);
        _tempFiles.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var f in _tempFiles)
        {
            try { File.Delete(f); } catch { /* best-effort cleanup */ }
        }
    }
}
