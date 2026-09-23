using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// firewall validate|generate|status|show|apply.
/// </summary>
internal static class FirewallCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var firewallCmd = new Command("firewall", "nftables ruleset generation, validation, and apply");

        var validateCmd = new Command("validate", "Validate Peer/Resource/Policy references and compute effective rules, without writing or applying anything");
        validateCmd.Options.Add(CommonOptions.Config);
        validateCmd.Options.Add(CommonOptions.Json);
        validateCmd.SetAction(async (parseResult, ct) =>
        {
            var json = parseResult.GetValue(CommonOptions.Json);
            var (config, peers, resources, policies, error) = await LoadFirewallInputsAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope();
            var generator = scope.ServiceProvider.GetRequiredService<IFirewallRuleGenerator>();
            var result = await generator.GenerateAsync(config, peers!, resources!, policies!, new FirewallGenerationOptions { DryRun = true }, ct);

            if (json)
            {
                OutputFormat.PrintJson(new { result.Success, effectiveRuleCount = result.EffectiveRules.Count, issues = result.ValidationIssues.Select(i => i.ToString()) });
            }
            else
            {
                foreach (var issue in result.ValidationIssues) Console.WriteLine(issue.ToString());
                Console.WriteLine($"Effective rules: {result.EffectiveRules.Count}");
                Console.WriteLine(result.Success ? "Result: VALID" : "Result: INVALID");
            }

            return result.Success ? ExitCodes.Success : ExitCodes.ValidationFailure;
        });

        var generateCmd = new Command("generate", "Render the nftables ruleset from current Peer/Resource/Policy state");
        generateCmd.Options.Add(CommonOptions.Config);
        generateCmd.Options.Add(CommonOptions.Output);
        generateCmd.Options.Add(CommonOptions.DryRun);
        generateCmd.Options.Add(CommonOptions.Force);
        generateCmd.Options.Add(CommonOptions.Json);
        generateCmd.SetAction(async (parseResult, ct) =>
        {
            var json = parseResult.GetValue(CommonOptions.Json);
            var (config, peers, resources, policies, error) = await LoadFirewallInputsAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            using var scope = services.CreateScope(dryRun);
            var generator = scope.ServiceProvider.GetRequiredService<IFirewallRuleGenerator>();
            var result = await generator.GenerateAsync(config, peers!, resources!, policies!, new FirewallGenerationOptions
            {
                DryRun = dryRun,
                Force = parseResult.GetValue(CommonOptions.Force),
                OutputPath = parseResult.GetValue(CommonOptions.Output)
            }, ct);

            if (json)
            {
                OutputFormat.PrintJson(new
                {
                    result.Success,
                    result.DryRun,
                    result.WrittenPath,
                    effectiveRuleCount = result.EffectiveRules.Count,
                    rendered = result.RenderedForReview,
                    issues = result.ValidationIssues.Select(i => i.ToString())
                });
            }
            else
            {
                Console.WriteLine("--- Rendered nftables ruleset (for review) ---");
                Console.WriteLine(result.RenderedForReview);
                foreach (var issue in result.ValidationIssues) Console.WriteLine(issue.ToString());
                Console.WriteLine(result.Success
                    ? (result.DryRun ? "[DRY-RUN] No file was written." : $"Written to: {result.WrittenPath}")
                    : "Result: FAILED (see issues above)");
            }

            return result.Success ? ExitCodes.Success : ExitCodes.ValidationFailure;
        });

        var statusCmd = new Command("status", "Show whether the SecureTunnel nftables table is present");
        statusCmd.Options.Add(CommonOptions.Json);
        statusCmd.SetAction(async (parseResult, ct) =>
        {
            using var scope = services.CreateScope();
            var firewallService = scope.ServiceProvider.GetRequiredService<IFirewallService>();
            var status = await firewallService.GetStatusAsync(ct);

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { status.State, status.Message });
            }
            else
            {
                Console.WriteLine(status.Message);
            }

            return status.State == FirewallTableState.Present ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });

        var showCmd = new Command("show", "Show `nft list table inet securetunnel` output (BLOCKED if nft is unavailable)");
        showCmd.Options.Add(CommonOptions.Json);
        showCmd.SetAction(async (parseResult, ct) =>
        {
            using var scope = services.CreateScope();
            var firewallService = scope.ServiceProvider.GetRequiredService<IFirewallService>();
            var output = await firewallService.ShowAsync(ct);

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { output });
            }
            else
            {
                Console.WriteLine(output);
            }

            return output.StartsWith("BLOCKED", StringComparison.Ordinal) ? ExitCodes.GeneralFailure : ExitCodes.Success;
        });

        var applyCmd = new Command("apply", "Generate, syntax-check, apply, and verify the nftables ruleset (requires --yes or --dry-run)");
        applyCmd.Options.Add(CommonOptions.Config);
        applyCmd.Options.Add(CommonOptions.DryRun);
        applyCmd.Options.Add(CommonOptions.Yes);
        applyCmd.Options.Add(CommonOptions.Json);
        applyCmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine("[ERROR] 'firewall apply' changes the running firewall. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, peers, resources, policies, error) = await LoadFirewallInputsAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope(dryRun);
            var orchestrator = scope.ServiceProvider.GetRequiredService<IFirewallApplyOrchestrator>();
            var result = await orchestrator.ApplyAsync(config, peers!, resources!, policies!, dryRun, ct);

            if (json)
            {
                OutputFormat.PrintJson(new { result.Success, result.DryRun, result.State, result.Message, issues = result.ValidationIssues.Select(i => i.ToString()) });
            }
            else
            {
                Console.WriteLine($"[{result.State}] {result.Message}");
                foreach (var issue in result.ValidationIssues) Console.WriteLine(issue.ToString());
            }

            return result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });

        firewallCmd.Subcommands.Add(validateCmd);
        firewallCmd.Subcommands.Add(generateCmd);
        firewallCmd.Subcommands.Add(statusCmd);
        firewallCmd.Subcommands.Add(showCmd);
        firewallCmd.Subcommands.Add(applyCmd);

        return firewallCmd;
    }

    private static async Task<(GatewayConfiguration? Config, IReadOnlyList<Peer>? Peers, IReadOnlyList<ProtectedResource>? Resources, IReadOnlyList<AccessPolicy>? Policies, string? Error)>
        LoadFirewallInputsAsync(IServiceProvider services, ParseResult parseResult, CancellationToken ct)
    {
        var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
        if (config is null)
        {
            return (null, null, null, null, error);
        }

        using var scope = services.CreateScope();
        var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
        var resourceService = scope.ServiceProvider.GetRequiredService<IResourceService>();
        var policyService = scope.ServiceProvider.GetRequiredService<IPolicyService>();

        try
        {
            var peers = await peerService.ListAsync(config, ct);
            var resources = await resourceService.ListAsync(config, ct);
            var policies = await policyService.ListAsync(config, ct);
            return (config, peers, resources, policies, null);
        }
        catch (Exception ex) when (ex is PeerRegistryCorruptException or ResourceRegistryCorruptException or PolicyRegistryCorruptException)
        {
            return (null, null, null, null, $"Registry error: {ex.Message}");
        }
    }
}
