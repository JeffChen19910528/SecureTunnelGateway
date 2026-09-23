using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.WireGuard;

/// <summary>
/// Operational control of the WireGuard interface. All operations go through
/// <see cref="Services.ISystemCommandExecutor"/> so they can be dry-run/mocked.
/// </summary>
public interface IWireGuardService
{
    Task<bool> CheckInstalledAsync(CancellationToken cancellationToken = default);
    Task<WireGuardStatus> GetStatusAsync(string interfaceName, CancellationToken cancellationToken = default);
    Task<CommandExecutionResult> StartAsync(string interfaceName, CancellationToken cancellationToken = default);
    Task<CommandExecutionResult> StopAsync(string interfaceName, CancellationToken cancellationToken = default);
    Task<CommandExecutionResult> RestartAsync(string interfaceName, CancellationToken cancellationToken = default);
    Task<string> ShowAsync(string interfaceName, CancellationToken cancellationToken = default);
    Task<string> CheckHandshakeAsync(string interfaceName, CancellationToken cancellationToken = default);
}
