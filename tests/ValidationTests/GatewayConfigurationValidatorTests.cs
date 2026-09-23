using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using Xunit;

namespace SecureTunnel.GatewayAgent.ValidationTests;

public sealed class GatewayConfigurationValidatorTests
{
    private readonly GatewayConfigurationValidator _validator = new();

    [Fact]
    public void Validate_KnownGoodConfiguration_IsValid()
    {
        var config = TestConfigurationFactory.CreateValid();

        var result = _validator.Validate(config);

        Assert.True(result.IsValid);
        Assert.Empty(result.Errors);
    }

    // --- CIDR ---

    [Theory]
    [InlineData("not-a-cidr")]
    [InlineData("10.250.0.0")]
    [InlineData("10.250.0.0/33")]
    [InlineData("10.250.0.0/-1")]
    [InlineData("300.1.1.0/24")]
    public void Validate_InvalidVpnCidr_ReturnsError(string badCidr)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.VpnCidr = badCidr;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.vpnCidr");
    }

    [Fact]
    public void Validate_OverlappingVpnAndProtectedCidr_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.VpnCidr = "10.20.0.0/24";
        // ProtectedNetworks already contains 10.20.0.0/24 from the factory.

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.vpnCidr" && e.Message.Contains("overlaps"));
    }

    [Fact]
    public void Validate_OverlappingProtectedNetworks_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ProtectedNetworks.Add(new() { Name = "overlap", Cidr = "10.20.0.128/25" });

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.protectedNetworks" && e.Message.Contains("overlaps"));
    }

    // --- IP range / pool ---

    [Fact]
    public void Validate_ClientPoolOutsideVpnCidr_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolEnd = "10.251.0.200"; // outside 10.250.0.0/24

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.clientAddressPool");
    }

    [Fact]
    public void Validate_GatewayIpOutsideVpnNetwork_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.GatewayVpnAddress = "192.168.1.1";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.gatewayVpnAddress");
    }

    [Fact]
    public void Validate_GatewayIpInsideClientPool_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.GatewayVpnAddress = "10.250.0.50"; // inside 10.250.0.10-10.250.0.200

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.gatewayVpnAddress" && e.Message.Contains("client address pool"));
    }

    [Fact]
    public void Validate_ClientPoolStartAfterEnd_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ClientAddressPoolStart = "10.250.0.200";
        config.Network.ClientAddressPoolEnd = "10.250.0.10";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.clientAddressPool" && e.Message.Contains("after"));
    }

    // --- Port ---

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(100000)]
    public void Validate_InvalidListenPort_ReturnsError(int port)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.ListenPort = port;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "wireGuard.listenPort");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(51820)]
    [InlineData(65535)]
    public void Validate_ValidListenPort_NoPortError(int port)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.ListenPort = port;

        var result = _validator.Validate(config);

        Assert.DoesNotContain(result.Errors, e => e.Field == "wireGuard.listenPort");
    }

    // --- Interface name ---

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("wg;rm -rf /")]
    [InlineData("wg securetunnel")]
    [InlineData("wg$(whoami)")]
    [InlineData("this-name-is-way-too-long-for-linux")]
    public void Validate_UnsafeInterfaceName_ReturnsError(string name)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.InterfaceName = name;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "wireGuard.interfaceName");
    }

    [Fact]
    public void Validate_InterfaceNameSameAsLanInterface_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.InterfaceName = "eth0";
        config.Network.LanInterface = "eth0";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "wireGuard.interfaceName" && e.Message.Contains("both"));
    }

    // --- Key path ---

    [Fact]
    public void Validate_EmptyPrivateKeyPath_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = "";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "wireGuard.privateKeyPath");
    }

    [Theory]
    [InlineData("/tmp/server.key")]
    [InlineData("/var/tmp/server.key")]
    [InlineData("/dev/shm/server.key")]
    public void Validate_UnsafeKeyPath_ReturnsError(string path)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = path;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "wireGuard.privateKeyPath");
    }

    // --- Routing mode ---

    [Fact]
    public void Validate_RoutedMode_ReturnsNotSupportedError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Routing.Mode = "routed";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "routing.mode" && e.Message.Contains("not supported"));
    }

    [Fact]
    public void Validate_UnknownRoutingMode_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Routing.Mode = "bridged";

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "routing.mode");
    }

    [Fact]
    public void Validate_NatModeWithNatDisabled_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Routing.Mode = "nat";
        config.Routing.NatEnabled = false;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "routing.natEnabled");
    }

    [Fact]
    public void Validate_Ipv6ForwardingWithoutAcknowledgement_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Routing.EnableIpv6Forwarding = true;
        config.Routing.Ipv6PolicyAcknowledged = false;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "routing.enableIpv6Forwarding");
    }

    [Fact]
    public void Validate_Ipv6ForwardingWithAcknowledgement_NoError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Routing.EnableIpv6Forwarding = true;
        config.Routing.Ipv6PolicyAcknowledged = true;

        var result = _validator.Validate(config);

        Assert.DoesNotContain(result.Errors, e => e.Field == "routing.enableIpv6Forwarding");
    }

    // --- Firewall policy / fail-closed / allow-all ---

    [Theory]
    [InlineData("allow")]
    [InlineData("permit")]
    [InlineData("")]
    public void Validate_NonDenyFirewallPolicy_ReturnsError(string policy)
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Security.FirewallDefaultPolicy = policy;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "security.firewallDefaultPolicy");
    }

    [Fact]
    public void Validate_FailClosedDisabled_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Security.FailClosed = false;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "security.failClosed");
    }

    [Fact]
    public void Validate_AllowUnlistedResourcesTrue_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Security.AllowUnlistedResources = true;

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "security.allowUnlistedResources");
    }

    // --- Duplicates / conflicts ---

    [Fact]
    public void Validate_DuplicateProtectedNetworkNames_ReturnsError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ProtectedNetworks.Add(new() { Name = "lab-protected-net", Cidr = "10.30.0.0/24" });

        var result = _validator.Validate(config);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "network.protectedNetworks" && e.Message.Contains("Duplicate"));
    }

    [Fact]
    public void Validate_NoProtectedNetworks_ReturnsWarningNotError()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Network.ProtectedNetworks.Clear();

        var result = _validator.Validate(config);

        Assert.True(result.IsValid);
        Assert.Contains(result.Warnings, w => w.Field == "network.protectedNetworks");
    }
}
