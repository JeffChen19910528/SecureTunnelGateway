using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Locates and executes scripts/validate-environment.sh via bash, then parses its
/// --json output into structured results. This intentionally reuses the shell script
/// (rather than re-implementing every OS/tool check in C#) so there is exactly one
/// place that defines "what does a healthy environment look like".
/// </summary>
public sealed class EnvironmentChecker : IEnvironmentChecker
{
    private readonly ISystemCommandExecutor _executor;
    private readonly ILogger<EnvironmentChecker> _logger;
    private readonly string? _explicitScriptPath;

    public EnvironmentChecker(ISystemCommandExecutor executor, ILogger<EnvironmentChecker> logger, string? explicitScriptPath = null)
    {
        _executor = executor;
        _logger = logger;
        _explicitScriptPath = explicitScriptPath;
    }

    public async Task<IReadOnlyList<EnvironmentCheckResult>> RunChecksAsync(CancellationToken cancellationToken = default)
    {
        var scriptPath = ResolveScriptPath();
        if (scriptPath is null)
        {
            return new[]
            {
                new EnvironmentCheckResult(
                    "environment.script",
                    CheckStatus.Blocked,
                    "Could not locate scripts/validate-environment.sh. Run it manually and consult docs/troubleshooting.md.")
            };
        }

        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "bash",
            Arguments = new[] { scriptPath, "--json" },
            Timeout = TimeSpan.FromSeconds(30)
        }, cancellationToken);

        if (string.IsNullOrWhiteSpace(result.StandardOutput))
        {
            _logger.LogWarning("validate-environment.sh produced no output (exit code {ExitCode}): {Stderr}", result.ExitCode, result.StandardError);
            return new[]
            {
                new EnvironmentCheckResult(
                    "environment.script",
                    CheckStatus.Blocked,
                    $"validate-environment.sh produced no output. stderr: {Truncate(result.StandardError)}")
            };
        }

        try
        {
            using var doc = JsonDocument.Parse(result.StandardOutput);
            var checks = doc.RootElement.GetProperty("checks");
            var results = new List<EnvironmentCheckResult>();
            foreach (var item in checks.EnumerateArray())
            {
                var id = item.GetProperty("id").GetString() ?? "unknown";
                var statusText = item.GetProperty("status").GetString() ?? "BLOCKED";
                var message = item.GetProperty("message").GetString() ?? string.Empty;
                results.Add(new EnvironmentCheckResult(id, ParseStatus(statusText), message));
            }
            return results;
        }
        catch (JsonException ex)
        {
            _logger.LogWarning(ex, "Failed to parse validate-environment.sh JSON output");
            return new[]
            {
                new EnvironmentCheckResult(
                    "environment.script",
                    CheckStatus.Blocked,
                    $"Could not parse validate-environment.sh output as JSON: {ex.Message}")
            };
        }
    }

    private static CheckStatus ParseStatus(string statusText) => statusText switch
    {
        "PASS" => CheckStatus.Pass,
        "WARN" => CheckStatus.Warn,
        "FAIL" => CheckStatus.Fail,
        "BLOCKED" => CheckStatus.Blocked,
        _ => CheckStatus.Blocked
    };

    private static string Truncate(string s, int max = 300) => s.Length <= max ? s : s[..max] + "...";

    private string? ResolveScriptPath()
    {
        if (_explicitScriptPath is not null && File.Exists(_explicitScriptPath))
        {
            return _explicitScriptPath;
        }

        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "scripts", "validate-environment.sh"),
            Path.Combine(Directory.GetCurrentDirectory(), "scripts", "validate-environment.sh"),
            "/opt/securetunnel-gateway/scripts/validate-environment.sh",
            "/etc/securetunnel-gateway/scripts/validate-environment.sh"
        };

        // Development convenience: walk up from the base directory looking for the repo's scripts/ folder.
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 6 && dir is not null; i++, dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "scripts", "validate-environment.sh");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return candidates.FirstOrDefault(File.Exists);
    }
}
