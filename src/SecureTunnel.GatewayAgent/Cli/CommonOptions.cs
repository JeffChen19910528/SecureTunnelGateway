using System.CommandLine;

namespace SecureTunnel.GatewayAgent.Cli;

/// <summary>Shared CLI options, reused across multiple subcommands.</summary>
public static class CommonOptions
{
    public static readonly Option<string> Config = new("--config")
    {
        Description = "Path to gateway.yaml (default: /etc/securetunnel-gateway/gateway.yaml)",
        DefaultValueFactory = _ => "/etc/securetunnel-gateway/gateway.yaml"
    };

    public static readonly Option<bool> Json = new("--json")
    {
        Description = "Output machine-readable JSON instead of human-readable text"
    };

    public static readonly Option<bool> DryRun = new("--dry-run")
    {
        Description = "Show what would happen without changing any system state"
    };

    public static readonly Option<bool> Force = new("--force")
    {
        Description = "Allow a normally-refused overwrite (e.g. an existing key or config file). Use with care."
    };

    public static readonly Option<bool> Yes = new("--yes")
    {
        Description = "Skip the interactive confirmation prompt for a destructive operation (for non-interactive/automation use)"
    };

    public static readonly Option<string?> Output = new("--output")
    {
        Description = "Output file path (defaults to the standard location for the target artifact)"
    };
}
