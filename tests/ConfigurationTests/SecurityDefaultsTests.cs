using SecureTunnel.GatewayAgent.Models;
using Xunit;

namespace SecureTunnel.GatewayAgent.ConfigurationTests;

/// <summary>
/// Verifies the "safe by default" contract from docs/security-model.md holds even when
/// a section is entirely absent from gateway.yaml (see YamlConfigurationLoaderTests.
/// Load_MissingSections_FallsBackToModelDefaults) - i.e. defaults live on the C# models
/// themselves, not only in the example YAML file.
/// </summary>
public sealed class SecurityDefaultsTests
{
    [Fact]
    public void SecurityConfiguration_Defaults_AreSafe()
    {
        var security = new SecurityConfiguration();

        Assert.Equal("deny", security.FirewallDefaultPolicy);
        Assert.True(security.FailClosed);
        Assert.False(security.AllowUnlistedResources);
        Assert.True(security.RequirePeerValidation);
    }

    [Fact]
    public void RoutingConfiguration_Defaults_AreSafe()
    {
        var routing = new RoutingConfiguration();

        Assert.Equal("nat", routing.Mode);
        Assert.True(routing.NatEnabled);
        Assert.False(routing.EnableIpv6Forwarding);
        Assert.False(routing.Ipv6PolicyAcknowledged);
        Assert.True(routing.EnableIpv4Forwarding);
    }

    [Fact]
    public void ControlPlaneConfiguration_Defaults_AreDisabled()
    {
        var controlPlane = new ControlPlaneConfiguration();

        Assert.False(controlPlane.Enabled);
        Assert.Equal(string.Empty, controlPlane.Endpoint);
    }

    [Fact]
    public void WireGuardConfiguration_Defaults_MatchDocumentedNetworkPlan()
    {
        var wg = new WireGuardConfiguration();

        Assert.Equal("wg-securetunnel", wg.InterfaceName);
        Assert.Equal(51820, wg.ListenPort);
        Assert.False(wg.SaveConfig);
    }

    [Fact]
    public void NetworkConfiguration_Defaults_MatchDocumentedNetworkPlan()
    {
        var net = new NetworkConfiguration();

        Assert.Equal("10.250.0.0/24", net.VpnCidr);
        Assert.Equal("10.250.0.1", net.GatewayVpnAddress);
        Assert.Equal("10.250.0.10", net.ClientAddressPoolStart);
        Assert.Equal("10.250.0.200", net.ClientAddressPoolEnd);
        Assert.Empty(net.ProtectedNetworks);
    }
}
