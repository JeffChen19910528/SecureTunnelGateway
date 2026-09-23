using System.CommandLine;
using SecureTunnel.GatewayAgent.Cli.Commands;

namespace SecureTunnel.GatewayAgent.Cli;

/// <summary>
/// Builds the `securetunnel-gateway` command tree. Every subcommand resolves its
/// dependencies from the DI container at invocation time (via <see cref="IServiceProvider"/>),
/// so the same command tree can be re-used with a normal executor or a dry-run/mock
/// executor depending on --dry-run and on what the caller registered - see Program.cs.
///
/// The actual command trees live one per domain under Cli/Commands/ (diagnostics,
/// config, wireguard, peer, resource, policy, firewall, gateway); this factory only
/// composes them under the root.
/// </summary>
public static class RootCommandFactory
{
    public static RootCommand Build(IServiceProvider rootServices)
    {
        var root = new RootCommand("SecureTunnel Gateway - VPN Gateway management CLI");

        root.Subcommands.Add(DiagnosticsCommands.BuildVersionCommand());
        root.Subcommands.Add(DiagnosticsCommands.BuildDoctorCommand(rootServices));
        root.Subcommands.Add(DiagnosticsCommands.BuildHealthCommand(rootServices));
        root.Subcommands.Add(DiagnosticsCommands.BuildValidateCommand(rootServices));
        root.Subcommands.Add(ConfigCommands.Build(rootServices));
        root.Subcommands.Add(WireGuardCommands.Build(rootServices));
        root.Subcommands.Add(PeerCommands.Build(rootServices));
        root.Subcommands.Add(ResourceCommands.Build(rootServices));
        root.Subcommands.Add(PolicyCommands.Build(rootServices));
        root.Subcommands.Add(FirewallCommands.Build(rootServices));
        root.Subcommands.Add(GatewayCommands.Build(rootServices));

        return root;
    }
}
