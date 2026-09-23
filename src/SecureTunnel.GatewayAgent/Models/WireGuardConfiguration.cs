namespace SecureTunnel.GatewayAgent.Models;

public sealed class WireGuardConfiguration
{
    /// <summary>WireGuard interface name, e.g. "wg-securetunnel".</summary>
    public string InterfaceName { get; set; } = "wg-securetunnel";

    public int ListenPort { get; set; } = 51820;

    /// <summary>Gateway's own address on the VPN interface, in CIDR form, e.g. "10.250.0.1/24".</summary>
    public string Address { get; set; } = string.Empty;

    /// <summary>
    /// Path to the server private key file on disk. The key content itself is never
    /// stored in this configuration object and never logged.
    /// </summary>
    public string PrivateKeyPath { get; set; } = string.Empty;

    /// <summary>Path to the server public key file on disk (public keys are not sensitive).</summary>
    public string PublicKeyPath { get; set; } = string.Empty;

    /// <summary>Whether wg-quick should persist runtime changes back into the config file.</summary>
    public bool SaveConfig { get; set; } = false;

    /// <summary>
    /// Publicly reachable hostname or IP that Clients should dial (e.g. "vpn.example.com").
    /// Optional: when absent, generated Client configuration templates use a placeholder
    /// that the operator must fill in (see Peers/ClientConfigTemplateGenerator).
    /// </summary>
    public string? EndpointHost { get; set; }

    /// <summary>
    /// Overrides where the applied wg-quick config file is written. Defaults to
    /// "/etc/wireguard/&lt;InterfaceName&gt;.conf" (the standard wg-quick location) when null -
    /// see Lifecycle/ConfigurationLifecycleService.ApplyWireGuardAsync. Exists mainly so
    /// tests can point at an isolated temp path instead of the real system location.
    /// </summary>
    public string? ConfigOutputPath { get; set; }
}
