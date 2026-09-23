using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class FirewallService : IFirewallService
{
    private const string TableName = "inet securetunnel";

    private readonly ISystemCommandExecutor _executor;
    private readonly ILogger<FirewallService> _logger;

    public FirewallService(ISystemCommandExecutor executor, ILogger<FirewallService> logger)
    {
        _executor = executor;
        _logger = logger;
    }

    public async Task<bool> CheckInstalledAsync(CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "nft",
            Arguments = new[] { "--version" },
            Timeout = TimeSpan.FromSeconds(5)
        }, cancellationToken);

        return result.Success;
    }

    public Task<CommandExecutionResult> ValidateSyntaxAsync(string rulesetPath, CancellationToken cancellationToken = default) =>
        RunNft(new[] { "-c", "-f", rulesetPath }, cancellationToken);

    public Task<CommandExecutionResult> ApplyAsync(string rulesetPath, CancellationToken cancellationToken = default) =>
        RunNft(new[] { "-f", rulesetPath }, cancellationToken);

    public Task<CommandExecutionResult> RemoveTableAsync(CancellationToken cancellationToken = default) =>
        RunNft(new[] { "delete", "table", "inet", "securetunnel" }, cancellationToken);

    public async Task<FirewallStatus> GetStatusAsync(CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "nft",
            Arguments = new[] { "list", "table", "inet", "securetunnel" },
            Timeout = TimeSpan.FromSeconds(10)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            return new FirewallStatus { State = FirewallTableState.Unknown, Message = "BLOCKED: 'nft' command not available on this host." };
        }

        if (!result.Success)
        {
            var stderr = result.StandardError.Trim();
            if (stderr.Contains("No such file or directory", StringComparison.OrdinalIgnoreCase) ||
                stderr.Contains("does not exist", StringComparison.OrdinalIgnoreCase))
            {
                return new FirewallStatus { State = FirewallTableState.NotPresent, Message = $"Table '{TableName}' does not exist yet (not applied)." };
            }

            return new FirewallStatus { State = FirewallTableState.Unknown, Message = $"'nft list table' failed: {Truncate(stderr)}" };
        }

        return new FirewallStatus { State = FirewallTableState.Present, RawOutput = result.StandardOutput, Message = $"Table '{TableName}' is present." };
    }

    public async Task<string> ShowAsync(CancellationToken cancellationToken = default)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "nft",
            Arguments = new[] { "list", "table", "inet", "securetunnel" },
            Timeout = TimeSpan.FromSeconds(10)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            return "BLOCKED: 'nft' command not available on this host.";
        }

        return result.Success ? result.StandardOutput : $"'nft list table' failed: {result.StandardError}";
    }

    private async Task<CommandExecutionResult> RunNft(string[] arguments, CancellationToken cancellationToken)
    {
        _logger.LogInformation("nft {Arguments}", string.Join(' ', arguments));

        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "nft",
            Arguments = arguments,
            Timeout = TimeSpan.FromSeconds(20)
        }, cancellationToken);

        if (result.ExitCode == -1)
        {
            _logger.LogWarning("BLOCKED: nft not available for '{Arguments}'", string.Join(' ', arguments));
        }
        else if (!result.Success)
        {
            _logger.LogWarning("nft {Arguments} failed with exit code {ExitCode}: {Stderr}", string.Join(' ', arguments), result.ExitCode, Truncate(result.StandardError));
        }

        return result;
    }

    private static string Truncate(string s, int max = 300) => s.Length <= max ? s : s[..max] + "...";
}
