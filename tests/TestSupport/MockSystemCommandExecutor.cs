using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.TestSupport;

/// <summary>
/// Test double for <see cref="ISystemCommandExecutor"/>. Records every invocation and
/// returns a scripted response, so WireGuard/Key/Health/CLI logic can be unit tested
/// without touching any real process, file system permission, or network state -
/// see docs/testing-guide.md, "B. Integration Tests".
/// </summary>
public sealed class MockSystemCommandExecutor : ISystemCommandExecutor
{
    public List<CommandExecutionRequest> Invocations { get; } = new();

    /// <summary>Queue of canned responses, consumed in order. If empty, a default success is returned.</summary>
    public Queue<CommandExecutionResult> Responses { get; } = new();

    /// <summary>Optional per-command override, keyed by executable name (e.g. "wg").</summary>
    public Dictionary<string, Func<CommandExecutionRequest, CommandExecutionResult>> Handlers { get; } = new();

    public Task<CommandExecutionResult> ExecuteAsync(CommandExecutionRequest request, CancellationToken cancellationToken = default)
    {
        Invocations.Add(request);

        if (Handlers.TryGetValue(request.Command, out var handler))
        {
            return Task.FromResult(handler(request));
        }

        if (Responses.Count > 0)
        {
            return Task.FromResult(Responses.Dequeue());
        }

        return Task.FromResult(new CommandExecutionResult
        {
            ExitCode = 0,
            StandardOutput = string.Empty,
            StandardError = string.Empty,
            TimedOut = false
        });
    }

    public static CommandExecutionResult Success(string stdout = "") => new()
    {
        ExitCode = 0,
        StandardOutput = stdout,
        StandardError = string.Empty,
        TimedOut = false
    };

    public static CommandExecutionResult Failure(int exitCode, string stderr) => new()
    {
        ExitCode = exitCode,
        StandardOutput = string.Empty,
        StandardError = stderr,
        TimedOut = false
    };

    public static CommandExecutionResult NotFound(string stderr) => new()
    {
        ExitCode = -1,
        StandardOutput = string.Empty,
        StandardError = stderr,
        TimedOut = false
    };
}
