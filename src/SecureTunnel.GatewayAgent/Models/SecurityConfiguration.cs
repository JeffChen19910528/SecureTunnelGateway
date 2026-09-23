namespace SecureTunnel.GatewayAgent.Models;

public sealed class SecurityConfiguration
{
    /// <summary>Must be "deny". Validation rejects any other value (see docs/security-model.md 第六節).</summary>
    public string FirewallDefaultPolicy { get; set; } = "deny";

    /// <summary>Must never default to true; validation rejects true (allow-all is forbidden).</summary>
    public bool AllowUnlistedResources { get; set; } = false;

    public bool RequirePeerValidation { get; set; } = true;

    /// <summary>Must be true; validation rejects false (see docs/security-model.md 第六節 Fail-Closed).</summary>
    public bool FailClosed { get; set; } = true;
}
