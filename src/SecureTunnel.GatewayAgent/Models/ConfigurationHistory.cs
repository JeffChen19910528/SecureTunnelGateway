namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// The full version history plus the two pointers that matter operationally: which
/// version is live (ActiveVersion) and which version is safe to roll back to
/// (LastKnownGoodVersion). Persisted as a single JSON file (see
/// Lifecycle/JsonFileConfigurationHistoryRepository.cs).
/// </summary>
public sealed class ConfigurationHistory
{
    public int? ActiveVersion { get; set; }

    /// <summary>
    /// The most recent version that was successfully Verified before the current Active
    /// version took over. Null until the first successful apply. Never silently cleared -
    /// see docs/security-model.md "Last Known Good".
    /// </summary>
    public int? LastKnownGoodVersion { get; set; }

    public List<ConfigurationSnapshot> Versions { get; set; } = new();
}
