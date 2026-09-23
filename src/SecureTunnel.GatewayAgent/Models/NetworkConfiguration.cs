namespace SecureTunnel.GatewayAgent.Models;

public sealed class NetworkConfiguration
{
    /// <summary>VPN network in CIDR form, e.g. "10.250.0.0/24" (see docs/network-topology.md).</summary>
    public string VpnCidr { get; set; } = "10.250.0.0/24";

    public string GatewayVpnAddress { get; set; } = "10.250.0.1";

    public string ClientAddressPoolStart { get; set; } = "10.250.0.10";
    public string ClientAddressPoolEnd { get; set; } = "10.250.0.200";

    /// <summary>Gateway network interface facing the protected network(s).</summary>
    public string LanInterface { get; set; } = string.Empty;

    public List<ProtectedNetworkDefinition> ProtectedNetworks { get; set; } = new();
}

public sealed class ProtectedNetworkDefinition
{
    public string Name { get; set; } = string.Empty;
    public string Cidr { get; set; } = string.Empty;
}
