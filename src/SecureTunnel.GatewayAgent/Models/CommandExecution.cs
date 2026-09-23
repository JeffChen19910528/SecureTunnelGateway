namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// A request to execute an external command. Arguments are always passed as a list
/// (never a pre-concatenated string) so callers cannot accidentally introduce shell
/// injection - see docs/security-model.md 第四節.
/// </summary>
public sealed class CommandExecutionRequest
{
    public required string Command { get; init; }
    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Optional data written to the process's standard input, used for handing secrets
    /// (e.g. a private key) to a command without exposing them as command-line arguments
    /// (which would otherwise be visible via `ps`).
    /// </summary>
    public string? StandardInput { get; init; }

    /// <summary>
    /// When true, callers indicate this command's output may contain sensitive data and
    /// executors/loggers must not print raw stdout/stderr.
    /// </summary>
    public bool SensitiveOutput { get; init; }

    public string DisplayCommandLine() =>
        $"{Command} {string.Join(' ', Arguments)}";
}

public sealed class CommandExecutionResult
{
    public required int ExitCode { get; init; }
    public required string StandardOutput { get; init; }
    public required string StandardError { get; init; }
    public bool TimedOut { get; init; }

    /// <summary>True only when the process actually ran, exited normally, and returned code 0.</summary>
    public bool Success => !TimedOut && ExitCode == 0;
}
