using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Backup;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Daemon;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// gateway status|backup|backup list|restore|serve.
///
/// `gateway health`/`diagnostics`/`version` are deliberately NOT separate commands
/// here - the existing top-level `health`/`doctor`/`version` (Phase 2) already cover
/// that ground, and duplicating them under `gateway` with a different name would only
/// create two ways to ask the same question. `gateway status` below is genuinely new:
/// it is the one place that shows Configured/Candidate(=Desired)/Active/Effective
/// state together, which none of the Phase 2 commands do on their own.
/// </summary>
internal static class GatewayCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var gatewayCmd = new Command("gateway", "Operational status, backup, and restore for the whole Gateway (Registries + WireGuard keys + Configuration History)");

        gatewayCmd.Subcommands.Add(BuildGatewayStatusCommand(services));
        gatewayCmd.Subcommands.Add(BuildGatewayBackupCommand(services));
        gatewayCmd.Subcommands.Add(BuildGatewayRestoreCommand(services));
        gatewayCmd.Subcommands.Add(BuildGatewayServeCommand(services));

        return gatewayCmd;
    }

    // -------------------------------------------------------------------
    // gateway serve (Phase 6A) - the real, persistent execution mode systemd's ExecStart
    // launches. See Daemon/GatewayDaemonService.cs for the startup-classification rationale.
    // -------------------------------------------------------------------
    private static Command BuildGatewayServeCommand(IServiceProvider services)
    {
        var intervalOption = new Option<int>("--interval-seconds")
        {
            Description = "Seconds between periodic Gateway state checks while running (default: 60)",
            DefaultValueFactory = _ => 60
        };
        var onceOption = new Option<bool>("--once")
        {
            Description = "Run startup validation and a single state check, then exit, instead of entering the persistent run loop (for scripted verification and testing)"
        };

        var cmd = new Command("serve", "Run the Gateway Agent as a persistent, systemd-managed service: startup validation, crash-recovery detection, and periodic state monitoring. Never applies configuration automatically - see docs/operations-guide.md \"Gateway Daemon\".");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(intervalOption);
        cmd.Options.Add(onceOption);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config)!;
            var intervalSeconds = Math.Max(1, parseResult.GetValue(intervalOption));
            var once = parseResult.GetValue(onceOption);

            using var scope = services.CreateScope();
            var daemon = scope.ServiceProvider.GetRequiredService<IGatewayDaemonService>();
            var options = new DaemonRunOptions { HealthCheckInterval = TimeSpan.FromSeconds(intervalSeconds), RunOnce = once };
            return await daemon.RunAsync(configPath, options, ct);
        });
        return cmd;
    }

    private static Command BuildGatewayStatusCommand(IServiceProvider services)
    {
        var cmd = new Command("status", "Comprehensive status: Configured, Desired (Candidate source), Active, and Effective state together");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var json = parseResult.GetValue(CommonOptions.Json);
            var configPath = parseResult.GetValue(CommonOptions.Config)!;

            using var scope = services.CreateScope();
            var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();

            GatewayConfiguration config;
            try
            {
                config = loader.Load(configPath);
            }
            catch (Exception ex)
            {
                var msg = $"Failed to load '{configPath}': {ex.Message}";
                if (json) OutputFormat.PrintJson(new { overallStatus = "Failed", configured = false, error = msg });
                else Console.Error.WriteLine($"[ERROR] {msg}");
                return ExitCodes.GeneralFailure;
            }

            var healthService = scope.ServiceProvider.GetRequiredService<IHealthCheckService>();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();

            var health = await healthService.CheckAsync(configPath, ct);
            var verify = await lifecycle.VerifyAsync(config, ct);
            var incomplete = await lifecycle.DetectIncompleteOperationAsync(config, ct);
            bool stale;
            ConfigurationHistory history;
            try
            {
                stale = await lifecycle.IsDesiredStaleAsync(config, ct);
                history = await lifecycle.GetHistoryAsync(config, ct);
            }
            catch (ConfigurationHistoryCorruptException ex)
            {
                var msg = $"Configuration history error: {ex.Message}";
                if (json) OutputFormat.PrintJson(new { overallStatus = "Failed", configured = true, error = msg });
                else Console.Error.WriteLine($"[ERROR] {msg}");
                return ExitCodes.GeneralFailure;
            }

            var toolsBlocked = health.Items.Any(i => i.Status == CheckStatus.Blocked && (i.Id == "wireguard-command" || i.Id == "nftables-command"));

            // Explicit, conservative precedence: an interrupted operation always wins (we
            // truly don't know the effective state), then a hard failure, then missing
            // tools, then "changes pending but not yet applied", then health's own signal.
            var overallStatus =
                incomplete is not null ? "Unknown" :
                health.OverallStatus == HealthStatus.Unhealthy ? "Failed" :
                toolsBlocked ? "Blocked" :
                stale || health.OverallStatus == HealthStatus.Degraded ? "Degraded" :
                "Healthy";

            if (json)
            {
                OutputFormat.PrintJson(new
                {
                    overallStatus,
                    configured = true,
                    desiredStale = stale,
                    activeVersion = history.ActiveVersion,
                    lastKnownGoodVersion = history.LastKnownGoodVersion,
                    incompleteOperation = incomplete,
                    effective = new { verify.WireGuardUp, verify.FirewallTablePresent, verify.EffectiveStateKnown },
                    health = health.OverallStatus,
                    healthItems = health.Items
                });
            }
            else
            {
                Console.WriteLine($"Overall status: {overallStatus}");
                Console.WriteLine($"  Configured: yes ({configPath})");
                Console.WriteLine($"  Desired vs Active: {(stale ? "DIFFERS (pending changes not yet applied - run `config apply`)" : "in sync")}");
                Console.WriteLine($"  Active version: {history.ActiveVersion?.ToString() ?? "(none)"}  Last known good: {history.LastKnownGoodVersion?.ToString() ?? "(none)"}");
                Console.WriteLine($"  Effective: {verify.Message}");
                if (incomplete is not null)
                {
                    Console.WriteLine($"  [WARNING] {incomplete}");
                }
                Console.WriteLine($"  Health: {health.OverallStatus}");
            }

            return overallStatus is "Healthy" or "Degraded" ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });
        return cmd;
    }

    private static Command BuildGatewayBackupCommand(IServiceProvider services)
    {
        var outputOption = new Option<string?>("--output") { Description = "Explicit archive path (default: a timestamped file under the configured backup directory)" };

        var backupCmd = new Command("backup", "Create or list operational backups (Registries + Configuration History + WireGuard keys)");

        var createCmd = new Command("create", "Create a new backup archive (this is the default action of `gateway backup`)");
        createCmd.Options.Add(CommonOptions.Config);
        createCmd.Options.Add(outputOption);
        createCmd.Options.Add(CommonOptions.DryRun);
        createCmd.Options.Add(CommonOptions.Json);
        createCmd.SetAction((parseResult, ct) => RunGatewayBackupCreate(services, parseResult, outputOption, ct));

        var listCmd = new Command("list", "List backup archives in the configured backup directory");
        listCmd.Options.Add(CommonOptions.Config);
        listCmd.Options.Add(CommonOptions.Json);
        listCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
            var entries = await backupService.ListAsync(config, ct);

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(entries.Select(e => new
                {
                    e.ArchivePath,
                    e.Readable,
                    e.Error,
                    createdAtUtc = e.Manifest?.CreatedAtUtc,
                    gatewayId = e.Manifest?.GatewayId,
                    fileCount = e.Manifest?.IncludedFiles.Count
                }));
            }
            else if (entries.Count == 0)
            {
                Console.WriteLine("No backups found.");
            }
            else
            {
                foreach (var e in entries)
                {
                    Console.WriteLine(e.Readable
                        ? $"{e.ArchivePath}  ({e.Manifest!.CreatedAtUtc:u}, gateway={e.Manifest.GatewayId}, {e.Manifest.IncludedFiles.Count} file(s))"
                        : $"{e.ArchivePath}  [UNREADABLE: {e.Error}]");
                }
            }

            return ExitCodes.Success;
        });

        // `gateway backup` with no further subcommand behaves like `gateway backup create`.
        backupCmd.Options.Add(CommonOptions.Config);
        backupCmd.Options.Add(outputOption);
        backupCmd.Options.Add(CommonOptions.DryRun);
        backupCmd.Options.Add(CommonOptions.Json);
        backupCmd.SetAction((parseResult, ct) => RunGatewayBackupCreate(services, parseResult, outputOption, ct));

        backupCmd.Subcommands.Add(createCmd);
        backupCmd.Subcommands.Add(listCmd);
        return backupCmd;
    }

    private static async Task<int> RunGatewayBackupCreate(IServiceProvider services, ParseResult parseResult, Option<string?> outputOption, CancellationToken ct)
    {
        var json = parseResult.GetValue(CommonOptions.Json);
        var dryRun = parseResult.GetValue(CommonOptions.DryRun);
        var configPath = parseResult.GetValue(CommonOptions.Config)!;
        var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
        if (config is null) return CommandHelpers.ReportLoadError(error!, json);

        using var scope = services.CreateScope();
        var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
        var result = await backupService.CreateAsync(config, configPath, parseResult.GetValue(outputOption), dryRun, ct);

        if (json)
        {
            OutputFormat.PrintJson(new { result.Success, result.DryRun, result.ArchivePath, result.Message, includedFiles = result.Manifest?.IncludedFiles });
        }
        else
        {
            Console.WriteLine(result.Message);
        }

        return result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure;
    }

    private static Command BuildGatewayRestoreCommand(IServiceProvider services)
    {
        var fileOption = new Option<string>("--file") { Description = "Path to the backup archive to restore", Required = true };

        var cmd = new Command("restore", "Restore Registries/History/WireGuard keys from a backup archive (requires --yes or --dry-run). Never activates the restored data - run `config apply` afterward.");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(fileOption);
        cmd.Options.Add(CommonOptions.DryRun);
        cmd.Options.Add(CommonOptions.Yes);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine("[ERROR] 'gateway restore' overwrites Registries, Configuration History, and WireGuard keys (previous files are preserved with a backup suffix). Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var configPath = parseResult.GetValue(CommonOptions.Config)!;
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope();
            var backupService = scope.ServiceProvider.GetRequiredService<IBackupService>();
            var result = await backupService.RestoreAsync(config, configPath, parseResult.GetValue(fileOption)!, dryRun, ct);

            if (json)
            {
                OutputFormat.PrintJson(new { result.Success, result.DryRun, result.Message, result.RestoredFiles });
            }
            else
            {
                Console.WriteLine(result.Message);
            }

            return result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });
        return cmd;
    }
}
