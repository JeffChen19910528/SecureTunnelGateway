namespace SecureTunnel.GatewayAgent.Models;

public sealed class LoggingConfiguration
{
    public string Level { get; set; } = "Information";
    public string AuditLogPath { get; set; } = "/var/log/securetunnel-gateway/audit.log";
    public string ApplicationLogPath { get; set; } = "/var/log/securetunnel-gateway/gateway.log";
}

public sealed class HealthCheckConfiguration
{
    public int IntervalSeconds { get; set; } = 30;
    public int DiskSpaceWarningPercent { get; set; } = 85;
    public int TimeSyncWarningSeconds { get; set; } = 10;
}

public sealed class ControlPlaneConfiguration
{
    /// <summary>Always false in this phase; field reserved for future integration (see docs/architecture.md 第十六節).</summary>
    public bool Enabled { get; set; } = false;
    public string Endpoint { get; set; } = string.Empty;
    public string CredentialReference { get; set; } = string.Empty;
}
