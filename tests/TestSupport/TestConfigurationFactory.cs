using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.TestSupport;

/// <summary>
/// Builds a known-valid <see cref="GatewayConfiguration"/> matching
/// config/gateway.example.yaml, so validation/generation tests can start from a valid
/// baseline and mutate exactly the field under test. Never contains a real private key -
/// PrivateKeyPath points at a path that is not expected to exist during unit tests.
/// </summary>
public static class TestConfigurationFactory
{
    public static GatewayConfiguration CreateValid()
    {
        return new GatewayConfiguration
        {
            GatewayId = "gw-test-001",
            GatewayName = "Test Gateway",
            OperatingSystem = "ubuntu-24.04",
            WireGuard = new WireGuardConfiguration
            {
                InterfaceName = "wg-securetunnel",
                ListenPort = 51820,
                Address = "10.250.0.1/24",
                PrivateKeyPath = "/etc/securetunnel-gateway/keys/server.key",
                PublicKeyPath = "/etc/securetunnel-gateway/keys/server.pub",
                SaveConfig = false
            },
            Network = new NetworkConfiguration
            {
                VpnCidr = "10.250.0.0/24",
                GatewayVpnAddress = "10.250.0.1",
                ClientAddressPoolStart = "10.250.0.10",
                ClientAddressPoolEnd = "10.250.0.200",
                LanInterface = "eth0",
                ProtectedNetworks = new List<ProtectedNetworkDefinition>
                {
                    new() { Name = "lab-protected-net", Cidr = "10.20.0.0/24" }
                }
            },
            Routing = new RoutingConfiguration
            {
                Mode = "nat",
                EnableIpv4Forwarding = true,
                EnableIpv6Forwarding = false,
                Ipv6PolicyAcknowledged = false,
                NatEnabled = true
            },
            Security = new SecurityConfiguration
            {
                FirewallDefaultPolicy = "deny",
                AllowUnlistedResources = false,
                RequirePeerValidation = true,
                FailClosed = true
            },
            Logging = new LoggingConfiguration
            {
                Level = "Information",
                AuditLogPath = "/var/log/securetunnel-gateway/audit.log",
                ApplicationLogPath = "/var/log/securetunnel-gateway/gateway.log"
            },
            HealthCheck = new HealthCheckConfiguration(),
            ControlPlane = new ControlPlaneConfiguration()
        };
    }
}
