using System.CommandLine;
using System.Reflection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// Top-level, read-only diagnostic commands: version, doctor, health, validate.
/// </summary>
internal static class DiagnosticsCommands
{
    internal static Command BuildVersionCommand()
    {
        var cmd = new Command("version", "Print the Gateway Agent version");
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(parseResult =>
        {
            var json = parseResult.GetValue(CommonOptions.Json);
            var version = Assembly.GetExecutingAssembly().GetName().Version?.ToString() ?? "0.0.0-dev";

            if (json)
            {
                OutputFormat.PrintJson(new { version, phase = "WireGuard Bootstrap" });
            }
            else
            {
                Console.WriteLine($"SecureTunnel Gateway Agent {version}");
            }

            return ExitCodes.Success;
        });
        return cmd;
    }

    internal static Command BuildDoctorCommand(IServiceProvider services)
    {
        var cmd = new Command("doctor", "Run a full environment and health diagnostic");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config);
            var json = parseResult.GetValue(CommonOptions.Json);

            using var scope = services.CreateScope();
            var environmentChecker = scope.ServiceProvider.GetRequiredService<IEnvironmentChecker>();
            var healthService = scope.ServiceProvider.GetRequiredService<IHealthCheckService>();

            var envChecks = await environmentChecker.RunChecksAsync(ct);
            var health = await healthService.CheckAsync(configPath, ct);

            if (json)
            {
                OutputFormat.PrintJson(new
                {
                    environment = envChecks,
                    health = new { health.OverallStatus, health.CheckedAtUtc, health.Items }
                });
            }
            else
            {
                Console.WriteLine("SecureTunnel Gateway - doctor");
                Console.WriteLine("==============================");
                Console.WriteLine();
                Console.WriteLine("Environment checks:");
                foreach (var c in envChecks)
                {
                    Console.WriteLine($"  [{c.Status,-7}] {c.Id,-32} {c.Message}");
                }
                Console.WriteLine();
                Console.WriteLine($"Overall health: {health.OverallStatus}");
                foreach (var item in health.Items)
                {
                    Console.WriteLine($"  [{item.Status,-7}] {item.Id,-32} {item.Message}");
                }
            }

            return health.OverallStatus == HealthStatus.Unhealthy ? ExitCodes.GeneralFailure : ExitCodes.Success;
        });
        return cmd;
    }

    internal static Command BuildHealthCommand(IServiceProvider services)
    {
        var cmd = new Command("health", "Report overall Gateway health (Healthy/Degraded/Unhealthy/Unknown)");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config);
            var json = parseResult.GetValue(CommonOptions.Json);

            using var scope = services.CreateScope();
            var healthService = scope.ServiceProvider.GetRequiredService<IHealthCheckService>();
            var report = await healthService.CheckAsync(configPath, ct);

            if (json)
            {
                OutputFormat.PrintJson(new { report.OverallStatus, report.CheckedAtUtc, report.Items });
            }
            else
            {
                Console.WriteLine($"Overall health: {report.OverallStatus}");
                foreach (var item in report.Items)
                {
                    Console.WriteLine($"  [{item.Status,-7}] {item.Id,-32} {item.Message}");
                }
            }

            return report.OverallStatus switch
            {
                HealthStatus.Healthy => ExitCodes.Success,
                HealthStatus.Degraded => ExitCodes.Success,
                HealthStatus.Unhealthy => ExitCodes.GeneralFailure,
                _ => ExitCodes.GeneralFailure
            };
        });
        return cmd;
    }

    internal static Command BuildValidateCommand(IServiceProvider services)
    {
        var cmd = new Command("validate", "Load and validate config/gateway.yaml without applying anything");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction((parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config)!;
            var json = parseResult.GetValue(CommonOptions.Json);

            using var scope = services.CreateScope();
            var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
            var validator = scope.ServiceProvider.GetRequiredService<IConfigurationValidator>();
            var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

            GatewayConfiguration config;
            try
            {
                config = loader.Load(configPath);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to load configuration from {Path}", configPath);
                if (json)
                {
                    OutputFormat.PrintJson(new { valid = false, error = ex.Message });
                }
                else
                {
                    Console.Error.WriteLine($"[ERROR] Failed to load '{configPath}': {ex.Message}");
                }
                return Task.FromResult(ExitCodes.ValidationFailure);
            }

            var result = validator.Validate(config);

            if (json)
            {
                OutputFormat.PrintJson(new
                {
                    valid = result.IsValid,
                    errors = result.Errors.Select(e => e.ToString()),
                    warnings = result.Warnings.Select(w => w.ToString())
                });
            }
            else
            {
                foreach (var issue in result.Issues)
                {
                    Console.WriteLine(issue.ToString());
                }
                Console.WriteLine(result.IsValid ? "Result: VALID" : "Result: INVALID");
            }

            return Task.FromResult(result.IsValid ? ExitCodes.Success : ExitCodes.ValidationFailure);
        });
        return cmd;
    }
}
