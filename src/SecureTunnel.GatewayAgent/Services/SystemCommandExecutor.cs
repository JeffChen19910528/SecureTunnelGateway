using System.Diagnostics;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Real implementation of <see cref="ISystemCommandExecutor"/>. Always launches processes
/// with an explicit argument list (never a shell-interpreted string), enforces a timeout,
/// and never logs stdout/stderr for requests marked <see cref="CommandExecutionRequest.SensitiveOutput"/>.
/// </summary>
public sealed class SystemCommandExecutor : ISystemCommandExecutor
{
    private readonly ILogger<SystemCommandExecutor> _logger;

    public SystemCommandExecutor(ILogger<SystemCommandExecutor> logger)
    {
        _logger = logger;
    }

    public async Task<CommandExecutionResult> ExecuteAsync(CommandExecutionRequest request, CancellationToken cancellationToken = default)
    {
        var logSafeCommandLine = request.SensitiveOutput
            ? $"{request.Command} [arguments redacted]"
            : request.DisplayCommandLine();

        _logger.LogInformation("Executing command: {CommandLine}", logSafeCommandLine);

        var startInfo = new ProcessStartInfo
        {
            FileName = request.Command,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = request.StandardInput is not null,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        foreach (var arg in request.Arguments)
        {
            startInfo.ArgumentList.Add(arg);
        }

        using var process = new Process { StartInfo = startInfo };
        using var timeoutCts = new CancellationTokenSource(request.Timeout);
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

        try
        {
            process.Start();
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or System.IO.FileNotFoundException)
        {
            _logger.LogWarning("Command not found or could not start: {Command} ({Error})", request.Command, ex.Message);
            return new CommandExecutionResult
            {
                ExitCode = -1,
                StandardOutput = string.Empty,
                StandardError = $"Failed to start '{request.Command}': {ex.Message}",
                TimedOut = false
            };
        }

        if (request.StandardInput is not null)
        {
            await process.StandardInput.WriteAsync(request.StandardInput);
            process.StandardInput.Close();
        }

        var stdoutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
        var stderrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);

        bool timedOut = false;
        try
        {
            await process.WaitForExitAsync(linkedCts.Token);
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested)
        {
            timedOut = true;
            TryKill(process);
        }

        string stdout, stderr;
        try
        {
            stdout = timedOut ? string.Empty : await stdoutTask;
            stderr = timedOut ? string.Empty : await stderrTask;
        }
        catch (OperationCanceledException)
        {
            stdout = string.Empty;
            stderr = string.Empty;
        }

        var exitCode = timedOut ? -1 : process.ExitCode;

        if (!request.SensitiveOutput)
        {
            _logger.LogDebug("Command {Command} exited with code {ExitCode}", request.Command, exitCode);
        }
        else
        {
            _logger.LogDebug("Command {Command} (sensitive output) exited with code {ExitCode}", request.Command, exitCode);
        }

        return new CommandExecutionResult
        {
            ExitCode = exitCode,
            StandardOutput = stdout,
            StandardError = stderr,
            TimedOut = timedOut
        };
    }

    private void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to kill timed-out process {Command}", process.StartInfo.FileName);
        }
    }
}
