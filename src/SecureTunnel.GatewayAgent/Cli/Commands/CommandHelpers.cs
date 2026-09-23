using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// Small pieces shared by every per-domain command builder (config loading and
/// error reporting) so each domain file below doesn't have to repeat them.
/// </summary>
internal static class CommandHelpers
{
    internal static async Task<(GatewayConfiguration? Config, string? Error)> LoadConfigAsync(IServiceProvider services, ParseResult parseResult, CancellationToken ct)
    {
        var configPath = parseResult.GetValue(CommonOptions.Config)!;
        using var scope = services.CreateScope();
        var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
        try
        {
            return (loader.Load(configPath), null);
        }
        catch (Exception ex)
        {
            return (null, $"Failed to load '{configPath}': {ex.Message}");
        }
    }

    internal static int ReportLoadError(string error, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(new { success = false, error });
        }
        else
        {
            Console.Error.WriteLine($"[ERROR] {error}");
        }
        return ExitCodes.ValidationFailure;
    }
}
