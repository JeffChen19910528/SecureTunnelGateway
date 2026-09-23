using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Operational control of the `inet securetunnel` nftables table via the `nft` command,
/// mirroring WireGuard/IWireGuardService.cs. All operations go through
/// Services.ISystemCommandExecutor so they can be dry-run/mocked, and every mutating
/// operation targets ONLY the SecureTunnel table - never a blanket `nft flush ruleset` or
/// any other table on the host.
/// </summary>
public interface IFirewallService
{
    Task<bool> CheckInstalledAsync(CancellationToken cancellationToken = default);

    /// <summary>Syntax-only check (`nft -c -f`) - does not modify kernel state.</summary>
    Task<CommandExecutionResult> ValidateSyntaxAsync(string rulesetPath, CancellationToken cancellationToken = default);

    /// <summary>Applies the ruleset file (`nft -f`). Only ever loads a file this Gateway generated.</summary>
    Task<CommandExecutionResult> ApplyAsync(string rulesetPath, CancellationToken cancellationToken = default);

    /// <summary>Removes only the SecureTunnel table (`nft delete table inet securetunnel`), never any other table.</summary>
    Task<CommandExecutionResult> RemoveTableAsync(CancellationToken cancellationToken = default);

    Task<FirewallStatus> GetStatusAsync(CancellationToken cancellationToken = default);

    Task<string> ShowAsync(CancellationToken cancellationToken = default);
}
