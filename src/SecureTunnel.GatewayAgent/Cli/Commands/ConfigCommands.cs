using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// config generate|status|list|show|diff|validate|apply|verify|rollback.
/// </summary>
internal static class ConfigCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var configCmd = new Command("config", "Gateway configuration lifecycle commands");

        var generateCmd = new Command("generate", "(Legacy/narrow) Render only the WireGuard interface configuration from gateway.yaml - alias of `wireguard generate`. For the full versioned lifecycle covering WireGuard AND nftables together, use `config apply`/`config validate` instead.");
        generateCmd.Options.Add(CommonOptions.Config);
        generateCmd.Options.Add(CommonOptions.Output);
        generateCmd.Options.Add(CommonOptions.DryRun);
        generateCmd.Options.Add(CommonOptions.Force);
        generateCmd.Options.Add(CommonOptions.Json);
        generateCmd.SetAction((parseResult, ct) => WireGuardCommands.GenerateWireGuardConfigAsync(services, parseResult, ct));

        configCmd.Subcommands.Add(generateCmd);
        configCmd.Subcommands.Add(BuildConfigStatusCommand(services));
        configCmd.Subcommands.Add(BuildConfigListCommand(services));
        configCmd.Subcommands.Add(BuildConfigShowCommand(services));
        configCmd.Subcommands.Add(BuildConfigDiffCommand(services));
        configCmd.Subcommands.Add(BuildConfigValidateCommand(services));
        configCmd.Subcommands.Add(BuildConfigApplyCommand(services));
        configCmd.Subcommands.Add(BuildConfigVerifyCommand(services));
        configCmd.Subcommands.Add(BuildConfigRollbackCommand(services));
        return configCmd;
    }

    private static Command BuildConfigStatusCommand(IServiceProvider services)
    {
        var cmd = new Command("status", "Show Active/Last-Known-Good version, latest version's state, and any interrupted operation");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();

            ConfigurationHistory history;
            try
            {
                history = await lifecycle.GetHistoryAsync(config, ct);
            }
            catch (ConfigurationHistoryCorruptException ex)
            {
                Console.Error.WriteLine($"[ERROR] Configuration history error: {ex.Message}");
                return ExitCodes.GeneralFailure;
            }

            var incomplete = await lifecycle.DetectIncompleteOperationAsync(config, ct);
            var latest = history.Versions.OrderByDescending(v => v.Version).FirstOrDefault();

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new
                {
                    history.ActiveVersion,
                    history.LastKnownGoodVersion,
                    latestVersion = latest?.Version,
                    latestState = latest?.State,
                    incompleteOperation = incomplete
                });
            }
            else
            {
                Console.WriteLine($"Active version: {history.ActiveVersion?.ToString() ?? "(none)"}");
                Console.WriteLine($"Last known good: {history.LastKnownGoodVersion?.ToString() ?? "(none)"}");
                if (latest is not null)
                {
                    Console.WriteLine($"Latest version: v{latest.Version} ({latest.State}) - {latest.SourceReason}");
                }
                if (incomplete is not null)
                {
                    Console.WriteLine($"[WARNING] {incomplete}");
                }
            }

            return incomplete is null ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });
        return cmd;
    }

    private static Command BuildConfigListCommand(IServiceProvider services)
    {
        var cmd = new Command("list", "List all recorded configuration versions");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
            var history = await lifecycle.GetHistoryAsync(config, ct);

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(history.Versions.OrderBy(v => v.Version).Select(v => new
                {
                    v.Version,
                    v.State,
                    v.CreatedAtUtc,
                    v.SourceReason,
                    v.EffectiveWireGuardPeerCount,
                    v.EffectiveFirewallRuleCount,
                    isActive = v.Version == history.ActiveVersion,
                    isLastKnownGood = v.Version == history.LastKnownGoodVersion
                }));
            }
            else if (history.Versions.Count == 0)
            {
                Console.WriteLine("No configuration versions recorded yet. Run `config apply` to create the first one.");
            }
            else
            {
                foreach (var v in history.Versions.OrderBy(x => x.Version))
                {
                    var marker = v.Version == history.ActiveVersion ? " [ACTIVE]" : v.Version == history.LastKnownGoodVersion ? " [LAST-KNOWN-GOOD]" : "";
                    Console.WriteLine($"v{v.Version,-4} {v.State,-20} {v.CreatedAtUtc:u}  {v.SourceReason}{marker}");
                }
            }

            return ExitCodes.Success;
        });
        return cmd;
    }

    private static Command BuildConfigShowCommand(IServiceProvider services)
    {
        var versionOption = new Option<int>("--version") { Description = "Configuration version number", Required = true };
        var cmd = new Command("show", "Show one configuration version's full detail");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(versionOption);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
            var snapshot = await lifecycle.GetVersionAsync(config, parseResult.GetValue(versionOption), ct);

            if (snapshot is null)
            {
                Console.Error.WriteLine("[ERROR] Version not found.");
                return ExitCodes.GeneralFailure;
            }

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new
                {
                    snapshot.Version,
                    snapshot.State,
                    snapshot.CreatedAtUtc,
                    snapshot.SourceReason,
                    snapshot.ContentHash,
                    snapshot.FailureReason,
                    snapshot.WireGuardApplied,
                    snapshot.FirewallApplied,
                    snapshot.RollbackTargetVersion,
                    snapshot.PreviousActiveVersion,
                    peers = snapshot.Peers.Select(p => new { p.PeerId, p.Name, p.Status, p.AssignedVpnIp }),
                    resources = snapshot.Resources.Select(r => new { r.ResourceId, r.Name, r.Destination, r.Protocol, r.Port, r.Enabled }),
                    policies = snapshot.Policies.Select(p => new { p.RuleId, p.PeerId, p.ResourceId, p.Enabled })
                });
            }
            else
            {
                Console.WriteLine($"Version {snapshot.Version} - {snapshot.State}");
                Console.WriteLine($"  Created: {snapshot.CreatedAtUtc:u}");
                Console.WriteLine($"  Reason: {snapshot.SourceReason}");
                Console.WriteLine($"  Content hash: {snapshot.ContentHash}");
                Console.WriteLine($"  WireGuard applied: {snapshot.WireGuardApplied}, Firewall applied: {snapshot.FirewallApplied}");
                if (snapshot.FailureReason is not null) Console.WriteLine($"  Failure reason: {snapshot.FailureReason}");
                Console.WriteLine($"  Peers: {snapshot.Peers.Count} ({snapshot.EffectiveWireGuardPeerCount} Active)");
                Console.WriteLine($"  Resources: {snapshot.Resources.Count}");
                Console.WriteLine($"  Policies: {snapshot.Policies.Count} ({snapshot.EffectiveFirewallRuleCount} effective)");
            }

            return ExitCodes.Success;
        });
        return cmd;
    }

    private static Command BuildConfigDiffCommand(IServiceProvider services)
    {
        var fromOption = new Option<int>("--from") { Description = "Base version", Required = true };
        var toOption = new Option<int>("--to") { Description = "Version to compare against the base", Required = true };
        var cmd = new Command("diff", "Show which Peers/Resources/Policies were added or removed between two versions");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(fromOption);
        cmd.Options.Add(toOption);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
            var from = await lifecycle.GetVersionAsync(config, parseResult.GetValue(fromOption), ct);
            var to = await lifecycle.GetVersionAsync(config, parseResult.GetValue(toOption), ct);

            if (from is null || to is null)
            {
                Console.Error.WriteLine("[ERROR] One or both versions were not found.");
                return ExitCodes.GeneralFailure;
            }

            var peersAdded = to.Peers.Select(p => p.PeerId).Except(from.Peers.Select(p => p.PeerId)).ToList();
            var peersRemoved = from.Peers.Select(p => p.PeerId).Except(to.Peers.Select(p => p.PeerId)).ToList();
            var resourcesAdded = to.Resources.Select(r => r.ResourceId).Except(from.Resources.Select(r => r.ResourceId)).ToList();
            var resourcesRemoved = from.Resources.Select(r => r.ResourceId).Except(to.Resources.Select(r => r.ResourceId)).ToList();
            var policiesAdded = to.Policies.Select(p => p.RuleId).Except(from.Policies.Select(p => p.RuleId)).ToList();
            var policiesRemoved = from.Policies.Select(p => p.RuleId).Except(to.Policies.Select(p => p.RuleId)).ToList();

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { peersAdded, peersRemoved, resourcesAdded, resourcesRemoved, policiesAdded, policiesRemoved });
            }
            else
            {
                Console.WriteLine($"Diff v{from.Version} -> v{to.Version}:");
                Console.WriteLine($"  Peers:     +{peersAdded.Count} -{peersRemoved.Count}");
                Console.WriteLine($"  Resources: +{resourcesAdded.Count} -{resourcesRemoved.Count}");
                Console.WriteLine($"  Policies:  +{policiesAdded.Count} -{policiesRemoved.Count}");
            }

            return ExitCodes.Success;
        });
        return cmd;
    }

    private static Command BuildConfigValidateCommand(IServiceProvider services)
    {
        var cmd = new Command("validate", "Validate the full candidate (gateway.yaml + Peers + Resources + Policies) without applying anything - equivalent to `config apply --dry-run`");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction((parseResult, ct) => RunConfigApply(services, parseResult, forcedDryRun: true, ct));
        return cmd;
    }

    private static Command BuildConfigApplyCommand(IServiceProvider services)
    {
        var cmd = new Command("apply", "Full versioned apply: validate, generate, apply WireGuard + nftables together, and verify (requires --yes or --dry-run)");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.DryRun);
        cmd.Options.Add(CommonOptions.Yes);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction((parseResult, ct) => RunConfigApply(services, parseResult, forcedDryRun: null, ct));
        return cmd;
    }

    private static async Task<int> RunConfigApply(IServiceProvider services, ParseResult parseResult, bool? forcedDryRun, CancellationToken ct)
    {
        var dryRun = forcedDryRun ?? parseResult.GetValue(CommonOptions.DryRun);
        var json = parseResult.GetValue(CommonOptions.Json);

        if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
        {
            Console.Error.WriteLine("[ERROR] 'config apply' changes the running WireGuard and nftables state together. Re-run with --yes to confirm (or --dry-run/`config validate` to preview).");
            return ExitCodes.GeneralFailure;
        }

        var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
        if (config is null) return CommandHelpers.ReportLoadError(error!, json);

        using var scope = services.CreateScope(dryRun);
        var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
        var result = await lifecycle.ApplyAsync(config, "manual apply via CLI", dryRun, ct);

        return ReportLifecycleResult(result, json);
    }

    private static Command BuildConfigVerifyCommand(IServiceProvider services)
    {
        var cmd = new Command("verify", "Check the ACTUAL current effective state (WireGuard interface + nftables table), independent of what history records");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
            var result = await lifecycle.VerifyAsync(config, ct);

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { result.WireGuardUp, result.FirewallTablePresent, result.EffectiveStateKnown, result.Message });
            }
            else
            {
                Console.WriteLine(result.Message);
            }

            return result.EffectiveStateKnown && result.WireGuardUp && result.FirewallTablePresent ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });
        return cmd;
    }

    private static Command BuildConfigRollbackCommand(IServiceProvider services)
    {
        var versionOption = new Option<int>("--version") { Description = "Version to roll back to", Required = true };
        var cmd = new Command("rollback", "Roll back to a previously-verified configuration version, using that version's own immutable snapshot data (requires --yes or --dry-run)");
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(versionOption);
        cmd.Options.Add(CommonOptions.DryRun);
        cmd.Options.Add(CommonOptions.Yes);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine("[ERROR] 'config rollback' changes the running WireGuard and nftables state together. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope(dryRun);
            var lifecycle = scope.ServiceProvider.GetRequiredService<IConfigurationLifecycleService>();
            var result = await lifecycle.RollbackAsync(config, parseResult.GetValue(versionOption), dryRun, ct);

            return ReportLifecycleResult(result, json);
        });
        return cmd;
    }

    private static int ReportLifecycleResult(ConfigurationApplyResult result, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(new
            {
                result.Success,
                result.DryRun,
                result.State,
                result.Version,
                result.Message,
                issues = result.ValidationIssues.Select(i => i.ToString())
            });
        }
        else
        {
            Console.WriteLine($"[{result.State}] {result.Message}");
            foreach (var issue in result.ValidationIssues) Console.WriteLine(issue.ToString());
        }

        if (!result.Success)
        {
            return result.State == ConfigurationState.ValidationFailed ? ExitCodes.ValidationFailure : ExitCodes.GeneralFailure;
        }
        return ExitCodes.Success;
    }
}
