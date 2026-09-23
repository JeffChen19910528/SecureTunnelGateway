using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// policy list|show|add|enable|disable|remove.
/// </summary>
internal static class PolicyCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var ruleIdOption = new Option<string>("--id") { Description = "Policy rule id (as shown by `policy list`)", Required = true };
        var peerIdOption = new Option<string>("--peer-id") { Description = "Peer id this policy grants access to", Required = true };
        var resourceIdOption = new Option<string>("--resource-id") { Description = "Resource id being granted", Required = true };
        var descriptionOption = new Option<string?>("--description") { Description = "Optional free-text description" };

        var policyCmd = new Command("policy", "Access Policy (Peer-to-Resource authorization) management");

        var listCmd = new Command("list", "List all access policies");
        listCmd.Options.Add(CommonOptions.Config);
        listCmd.Options.Add(CommonOptions.Json);
        listCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var policyService = scope.ServiceProvider.GetRequiredService<IPolicyService>();
            try
            {
                var policies = await policyService.ListAsync(config, ct);
                PrintPolicyList(policies, parseResult.GetValue(CommonOptions.Json));
                return ExitCodes.Success;
            }
            catch (PolicyRegistryCorruptException ex)
            {
                Console.Error.WriteLine($"[ERROR] Policy registry error: {ex.Message}");
                return ExitCodes.GeneralFailure;
            }
        });

        var showCmd = new Command("show", "Show a single policy's details");
        showCmd.Options.Add(CommonOptions.Config);
        showCmd.Options.Add(ruleIdOption);
        showCmd.Options.Add(CommonOptions.Json);
        showCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var policyService = scope.ServiceProvider.GetRequiredService<IPolicyService>();
            var policy = await policyService.GetAsync(config, parseResult.GetValue(ruleIdOption)!, ct);
            if (policy is null)
            {
                Console.Error.WriteLine("[ERROR] Policy not found.");
                return ExitCodes.GeneralFailure;
            }

            PrintPolicyList(new[] { policy }, parseResult.GetValue(CommonOptions.Json));
            return ExitCodes.Success;
        });

        var addCmd = new Command("add", "Grant a peer access to a resource (requires --yes or --dry-run)");
        addCmd.Options.Add(CommonOptions.Config);
        addCmd.Options.Add(peerIdOption);
        addCmd.Options.Add(resourceIdOption);
        addCmd.Options.Add(descriptionOption);
        addCmd.Options.Add(CommonOptions.DryRun);
        addCmd.Options.Add(CommonOptions.Yes);
        addCmd.Options.Add(CommonOptions.Json);
        addCmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine("[ERROR] 'policy add' grants access to a protected resource. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope();
            var policyService = scope.ServiceProvider.GetRequiredService<IPolicyService>();
            var result = await policyService.AddAsync(config, parseResult.GetValue(peerIdOption)!, parseResult.GetValue(resourceIdOption)!,
                parseResult.GetValue(descriptionOption), dryRun, ct);

            return ReportPolicyResult(result, json);
        });

        var enableCmd = BuildPolicyTransitionCommand("enable", "Re-enable a disabled policy (requires --yes or --dry-run)", services, ruleIdOption,
            (svc, config, id, dryRun, ct) => svc.EnableAsync(config, id, dryRun, ct));
        var disableCmd = BuildPolicyTransitionCommand("disable", "Disable a policy without deleting it (requires --yes or --dry-run)", services, ruleIdOption,
            (svc, config, id, dryRun, ct) => svc.DisableAsync(config, id, dryRun, ct));
        var removeCmd = BuildPolicyTransitionCommand("remove", "Permanently delete a policy (requires --yes or --dry-run)", services, ruleIdOption,
            (svc, config, id, dryRun, ct) => svc.RemoveAsync(config, id, dryRun, ct));

        policyCmd.Subcommands.Add(listCmd);
        policyCmd.Subcommands.Add(showCmd);
        policyCmd.Subcommands.Add(addCmd);
        policyCmd.Subcommands.Add(enableCmd);
        policyCmd.Subcommands.Add(disableCmd);
        policyCmd.Subcommands.Add(removeCmd);

        return policyCmd;
    }

    private static Command BuildPolicyTransitionCommand(
        string name, string description, IServiceProvider services, Option<string> ruleIdOption,
        Func<IPolicyService, GatewayConfiguration, string, bool, CancellationToken, Task<PolicyOperationResult>> action)
    {
        var cmd = new Command(name, description);
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(ruleIdOption);
        cmd.Options.Add(CommonOptions.DryRun);
        cmd.Options.Add(CommonOptions.Yes);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine($"[ERROR] '{name}' is a security-sensitive operation. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            using var scope = services.CreateScope();
            var policyService = scope.ServiceProvider.GetRequiredService<IPolicyService>();
            var result = await action(policyService, config, parseResult.GetValue(ruleIdOption)!, dryRun, ct);

            return ReportPolicyResult(result, json);
        });
        return cmd;
    }

    private static int ReportPolicyResult(PolicyOperationResult result, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(new
            {
                result.Success,
                result.DryRun,
                result.FailureKind,
                result.Message,
                policy = result.Policy is null ? null : new { result.Policy.RuleId, result.Policy.PeerId, result.Policy.ResourceId, result.Policy.Enabled },
                issues = result.Issues.Select(i => i.ToString())
            });
        }
        else
        {
            Console.WriteLine(result.Message);
            if (result.Policy is not null)
            {
                Console.WriteLine($"  RuleId: {result.Policy.RuleId}, Peer: {result.Policy.PeerId}, Resource: {result.Policy.ResourceId}, Enabled: {result.Policy.Enabled}");
            }
            foreach (var issue in result.Issues)
            {
                Console.WriteLine(issue.ToString());
            }
        }

        if (!result.Success)
        {
            return result.FailureKind == PeerOperationFailureKind.ValidationFailed ? ExitCodes.ValidationFailure : ExitCodes.GeneralFailure;
        }
        return ExitCodes.Success;
    }

    private static void PrintPolicyList(IReadOnlyList<AccessPolicy> policies, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(policies.Select(p => new { p.RuleId, p.PeerId, p.ResourceId, p.Enabled, p.Description, p.CreatedAtUtc, p.UpdatedAtUtc }));
            return;
        }

        if (policies.Count == 0)
        {
            Console.WriteLine("No policies registered.");
            return;
        }

        foreach (var p in policies)
        {
            Console.WriteLine($"{p.RuleId,-16} {(p.Enabled ? "Enabled " : "Disabled")} peer:{p.PeerId,-18} -> resource:{p.ResourceId}");
        }
    }
}
