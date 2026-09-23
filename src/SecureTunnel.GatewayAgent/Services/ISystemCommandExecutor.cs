using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Sole abstraction through which SecureTunnel Gateway executes external Linux commands
/// (wg, wg-quick, nft, ip, sysctl, systemctl, ...). Domain/validation logic must never
/// call Process.Start directly - see docs/security-model.md 第四節 and CONTRIBUTING.md.
/// </summary>
public interface ISystemCommandExecutor
{
    Task<CommandExecutionResult> ExecuteAsync(CommandExecutionRequest request, CancellationToken cancellationToken = default);
}
