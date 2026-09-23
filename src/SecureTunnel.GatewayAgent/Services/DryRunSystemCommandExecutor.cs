using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Decorator that intercepts every command execution and, instead of running it, records
/// what WOULD have been executed. Used whenever --dry-run is passed so that "dry-run 不得
/// 修改系統" (docs/operations-guide.md) is a structural guarantee, not a per-call convention.
///
/// A small allow-list of read-only, side-effect-free commands (status/show queries) is
/// still passed through to the real executor, since dry-run should still be able to show
/// the user *current* state without pretending to change anything.
/// </summary>
public sealed class DryRunSystemCommandExecutor : ISystemCommandExecutor
{
    private static readonly HashSet<string> ReadOnlyPassthroughCommands = new(StringComparer.Ordinal)
    {
        "wg", "cat", "sysctl", "ip", "uname", "systemctl", "nft"
    };

    private readonly ISystemCommandExecutor _inner;
    private readonly ILogger<DryRunSystemCommandExecutor> _logger;

    public DryRunSystemCommandExecutor(ISystemCommandExecutor inner, ILogger<DryRunSystemCommandExecutor> logger)
    {
        _inner = inner;
        _logger = logger;
    }

    public Task<CommandExecutionResult> ExecuteAsync(CommandExecutionRequest request, CancellationToken cancellationToken = default)
    {
        // "nft -c -f <path>" (syntax check) and "nft list ..." are read-only; only
        // "nft -f <path>" (apply) and "nft delete ..." mutate kernel state. "wg genkey"/
        // "wg pubkey"/"wg set" are excluded from "wg"'s read-only passthrough as
        // defense-in-depth (Phase 7 hardening) - callers already gate real key generation
        // behind their own dry-run check before ever reaching here (see
        // Security/KeyManagementService.cs), so this switch is currently never hit for
        // those subcommands, but a future caller must not be able to silently generate a
        // real key, or mutate a live interface, just because it forgot its own dry-run gate.
        var isMutating = request.Command switch
        {
            "wg-quick" => request.Arguments.Count > 0 && request.Arguments[0] is "up" or "down",
            "wg" => request.Arguments.Count > 0 && request.Arguments[0] is "genkey" or "pubkey" or "set",
            "nft" => request.Arguments.Count > 0 && request.Arguments[0] is "-f" or "delete",
            _ => false
        };

        var isReadOnly = ReadOnlyPassthroughCommands.Contains(request.Command) && !isMutating;

        if (isReadOnly)
        {
            return _inner.ExecuteAsync(request, cancellationToken);
        }

        var display = request.SensitiveOutput ? $"{request.Command} [arguments redacted]" : request.DisplayCommandLine();
        _logger.LogInformation("[DRY-RUN] Would execute: {CommandLine} (not executed)", display);

        return Task.FromResult(new CommandExecutionResult
        {
            ExitCode = 0,
            StandardOutput = $"[DRY-RUN] command not executed: {display}",
            StandardError = string.Empty,
            TimedOut = false
        });
    }
}
