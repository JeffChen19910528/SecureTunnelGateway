using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.WireGuard;

public sealed class WireGuardService : IWireGuardService
{
    private readonly ISystemCommandExecutor _executor;
    private readonly ILogger<WireGuardService> _logger;

    public WireGuardService(ISystemCommandExecutor executor, ILogger<WireGuardService> logger)
    {
        _executor = executor;
        _logger = logger;
    }

    public async Task<bool> CheckInstalledAsync(CancellationToken cancellationToken = default)
    {
        var wg = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "--version" },
            Timeout = TimeSpan.FromSeconds(5)
        }, cancellationToken);

        var wgQuick = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg-quick",
            Arguments = new[] { "--help" },
            Timeout = TimeSpan.FromSeconds(5)
        }, cancellationToken);

        // wg-quick --help exits non-zero on some versions while still printing usage,
        // so treat "process started" (ExitCode != -1) as sufficient evidence it exists.
        return wg.Success && wgQuick.ExitCode != -1;
    }

    public async Task<WireGuardStatus> GetStatusAsync(string interfaceName, CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "show", interfaceName },
            Timeout = TimeSpan.FromSeconds(10)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            return new WireGuardStatus
            {
                State = WireGuardInterfaceState.Unknown,
                Message = "BLOCKED: could not run 'wg show' (wireguard-tools not installed on this host)."
            };
        }

        if (!result.Success)
        {
            var stderr = result.StandardError.Trim();
            if (stderr.Contains("No such device", StringComparison.OrdinalIgnoreCase))
            {
                return new WireGuardStatus
                {
                    State = WireGuardInterfaceState.NotConfigured,
                    Message = $"Interface '{interfaceName}' does not exist yet."
                };
            }

            return new WireGuardStatus
            {
                State = WireGuardInterfaceState.Unknown,
                Message = $"'wg show {interfaceName}' failed: {Truncate(stderr)}"
            };
        }

        return new WireGuardStatus
        {
            State = WireGuardInterfaceState.Up,
            RawOutput = result.StandardOutput,
            Message = $"Interface '{interfaceName}' is up."
        };
    }

    public Task<CommandExecutionResult> StartAsync(string interfaceName, CancellationToken cancellationToken = default) =>
        RunWgQuick("up", interfaceName, cancellationToken);

    public Task<CommandExecutionResult> StopAsync(string interfaceName, CancellationToken cancellationToken = default) =>
        RunWgQuick("down", interfaceName, cancellationToken);

    public async Task<CommandExecutionResult> RestartAsync(string interfaceName, CancellationToken cancellationToken = default)
    {
        var stop = await StopAsync(interfaceName, cancellationToken);
        if (!stop.Success)
        {
            _logger.LogWarning("Restart: 'wg-quick down {Interface}' did not succeed (exit code {ExitCode}); attempting start anyway.",
                interfaceName, stop.ExitCode);
        }

        return await StartAsync(interfaceName, cancellationToken);
    }

    public async Task<string> ShowAsync(string interfaceName, CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "show", interfaceName },
            Timeout = TimeSpan.FromSeconds(10)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            return "BLOCKED: 'wg' command not available on this host.";
        }

        return result.Success ? result.StandardOutput : $"'wg show' failed: {result.StandardError}";
    }

    public async Task<string> CheckHandshakeAsync(string interfaceName, CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "show", interfaceName, "latest-handshakes" },
            Timeout = TimeSpan.FromSeconds(10)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            return "BLOCKED: 'wg' command not available on this host.";
        }

        return result.Success ? result.StandardOutput : $"'wg show latest-handshakes' failed: {result.StandardError}";
    }

    private async Task<CommandExecutionResult> RunWgQuick(string action, string interfaceName, CancellationToken cancellationToken)
    {
        _logger.LogInformation("wg-quick {Action} {Interface}", action, interfaceName);

        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg-quick",
            Arguments = new[] { action, interfaceName },
            Timeout = TimeSpan.FromSeconds(20)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            _logger.LogWarning("BLOCKED: wg-quick not available for '{Action} {Interface}'", action, interfaceName);
        }
        else if (!result.Success)
        {
            _logger.LogWarning("wg-quick {Action} {Interface} failed with exit code {ExitCode}: {Stderr}",
                action, interfaceName, result.ExitCode, Truncate(result.StandardError));
        }

        return result;
    }

    private static string Truncate(string s, int max = 300) => s.Length <= max ? s : s[..max] + "...";
}
