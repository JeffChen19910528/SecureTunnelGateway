namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Root configuration model, deserialized from config/gateway.yaml (see
/// config/gateway.example.yaml and docs/configuration-guide.md).
/// </summary>
public sealed class GatewayConfiguration
{
    public string GatewayId { get; set; } = string.Empty;
    public string GatewayName { get; set; } = string.Empty;

    /// <summary>Informational description of the intended target OS, e.g. "ubuntu-24.04".</summary>
    public string OperatingSystem { get; set; } = "ubuntu-24.04";

    public WireGuardConfiguration WireGuard { get; set; } = new();
    public NetworkConfiguration Network { get; set; } = new();
    public RoutingConfiguration Routing { get; set; } = new();
    public SecurityConfiguration Security { get; set; } = new();
    public LoggingConfiguration Logging { get; set; } = new();
    public HealthCheckConfiguration HealthCheck { get; set; } = new();
    public ControlPlaneConfiguration ControlPlane { get; set; } = new();

    // --- Mutable state (see docs/installation-guide.md "Linux Deployment Layout") ---
    // Phase 6 moved these from /etc/securetunnel-gateway to /var/lib/securetunnel-gateway:
    // /etc is conventionally for static configuration an admin edits by hand (gateway.yaml,
    // the WireGuard key files); everything below is data the Gateway Agent itself reads and
    // rewrites at runtime, which belongs under /var/lib per the FHS. Nothing outside this
    // model's own field defaults depended on the old /etc paths, so this is a pure default
    // change, not a breaking one for anyone who already set these explicitly in gateway.yaml.

    /// <summary>
    /// Path to the peer registry JSON file (see Peers/JsonFilePeerRepository). Contains
    /// only Peer metadata and public keys - never private keys.
    /// </summary>
    public string PeerStorePath { get; set; } = "/var/lib/securetunnel-gateway/peers.json";

    /// <summary>Path to the Protected Resource registry JSON file (see Firewall/JsonFileResourceRepository).</summary>
    public string ResourceStorePath { get; set; } = "/var/lib/securetunnel-gateway/resources.json";

    /// <summary>Path to the Access Policy registry JSON file (see Firewall/JsonFilePolicyRepository).</summary>
    public string PolicyStorePath { get; set; } = "/var/lib/securetunnel-gateway/policies.json";

    /// <summary>Path the generated/applied nftables ruleset file is written to (see Firewall/FirewallRuleGenerator).</summary>
    public string FirewallRulesetPath { get; set; } = "/var/lib/securetunnel-gateway/nftables/securetunnel.conf";

    /// <summary>
    /// Path to the Configuration History file (see Lifecycle/JsonFileConfigurationHistoryRepository).
    /// Tracks every candidate/active configuration version and their outcomes - never
    /// contains private key material (see docs/security-model.md).
    /// </summary>
    public string ConfigurationHistoryPath { get; set; } = "/var/lib/securetunnel-gateway/config-history.json";

    /// <summary>Path to the single-writer operation lock file (see Lifecycle/FileOperationLock).</summary>
    public string OperationLockPath { get; set; } = "/var/lib/securetunnel-gateway/gateway.lock";

    /// <summary>Directory backup archives are written to and listed from by default (see Backup/IBackupService).</summary>
    public string BackupDirectory { get; set; } = "/var/lib/securetunnel-gateway/backups";
}
