using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// resource list|show|add|enable|disable|remove.
/// </summary>
internal static class ResourceCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var idOption = new Option<string>("--id") { Description = "Resource id (as shown by `resource list`)", Required = true };
        var nameOption = new Option<string>("--name") { Description = "Human-readable resource name", Required = true };
        var destinationOption = new Option<string>("--destination") { Description = "Explicit IPv4 address or CIDR - never a hostname", Required = true };
        var protocolOption = new Option<string>("--protocol") { Description = "tcp | udp", Required = true };
        var portOption = new Option<int>("--port") { Description = "Destination port (or start of a range)", Required = true };
        var portEndOption = new Option<int?>("--port-end") { Description = "End of the port range (inclusive); omit for a single port" };
        var descriptionOption = new Option<string?>("--description") { Description = "Optional free-text description" };

        var resourceCmd = new Command("resource", "Protected Resource registration and lifecycle management");

        var listCmd = new Command("list", "List all registered resources");
        listCmd.Options.Add(CommonOptions.Config);
        listCmd.Options.Add(CommonOptions.Json);
        listCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var resourceService = scope.ServiceProvider.GetRequiredService<IResourceService>();
            try
            {
                var resources = await resourceService.ListAsync(config, ct);
                PrintResourceList(resources, parseResult.GetValue(CommonOptions.Json));
                return ExitCodes.Success;
            }
            catch (ResourceRegistryCorruptException ex)
            {
                Console.Error.WriteLine($"[ERROR] Resource registry error: {ex.Message}");
                return ExitCodes.GeneralFailure;
            }
        });

        var showCmd = new Command("show", "Show a single resource's details");
        showCmd.Options.Add(CommonOptions.Config);
        showCmd.Options.Add(idOption);
        showCmd.Options.Add(CommonOptions.Json);
        showCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var resourceService = scope.ServiceProvider.GetRequiredService<IResourceService>();
            var resource = await resourceService.GetAsync(config, parseResult.GetValue(idOption)!, ct);
            if (resource is null)
            {
                Console.Error.WriteLine("[ERROR] Resource not found.");
                return ExitCodes.GeneralFailure;
            }

            PrintResourceList(new[] { resource }, parseResult.GetValue(CommonOptions.Json));
            return ExitCodes.Success;
        });

        var addCmd = new Command("add", "Register a new protected resource (requires --yes or --dry-run)");
        addCmd.Options.Add(CommonOptions.Config);
        addCmd.Options.Add(nameOption);
        addCmd.Options.Add(destinationOption);
        addCmd.Options.Add(protocolOption);
        addCmd.Options.Add(portOption);
        addCmd.Options.Add(portEndOption);
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
                Console.Error.WriteLine("[ERROR] 'resource add' changes what is reachable through the Gateway. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            if (!TryParseProtocol(parseResult.GetValue(protocolOption), out var protocol))
            {
                Console.Error.WriteLine("[ERROR] --protocol must be 'tcp' or 'udp'.");
                return ExitCodes.ValidationFailure;
            }

            using var scope = services.CreateScope();
            var resourceService = scope.ServiceProvider.GetRequiredService<IResourceService>();
            var result = await resourceService.AddAsync(config, parseResult.GetValue(nameOption)!, parseResult.GetValue(destinationOption)!,
                protocol, parseResult.GetValue(portOption), parseResult.GetValue(portEndOption), parseResult.GetValue(descriptionOption), dryRun, ct);

            return ReportResourceResult(result, json);
        });

        var enableCmd = BuildResourceTransitionCommand("enable", "Re-enable a disabled resource (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.EnableAsync(config, id, dryRun, ct));
        var disableCmd = BuildResourceTransitionCommand("disable", "Disable a resource; effective rules referencing it are excluded (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.DisableAsync(config, id, dryRun, ct));
        var removeCmd = BuildResourceTransitionCommand("remove", "Permanently delete a resource (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.RemoveAsync(config, id, dryRun, ct));

        resourceCmd.Subcommands.Add(listCmd);
        resourceCmd.Subcommands.Add(showCmd);
        resourceCmd.Subcommands.Add(addCmd);
        resourceCmd.Subcommands.Add(enableCmd);
        resourceCmd.Subcommands.Add(disableCmd);
        resourceCmd.Subcommands.Add(removeCmd);

        return resourceCmd;
    }

    private static Command BuildResourceTransitionCommand(
        string name, string description, IServiceProvider services, Option<string> idOption,
        Func<IResourceService, GatewayConfiguration, string, bool, CancellationToken, Task<ResourceOperationResult>> action)
    {
        var cmd = new Command(name, description);
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(idOption);
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
            var resourceService = scope.ServiceProvider.GetRequiredService<IResourceService>();
            var result = await action(resourceService, config, parseResult.GetValue(idOption)!, dryRun, ct);

            return ReportResourceResult(result, json);
        });
        return cmd;
    }

    private static bool TryParseProtocol(string? value, out Protocol protocol)
    {
        switch (value?.Trim().ToLowerInvariant())
        {
            case "tcp": protocol = Protocol.Tcp; return true;
            case "udp": protocol = Protocol.Udp; return true;
            default: protocol = Protocol.Tcp; return false;
        }
    }

    private static int ReportResourceResult(ResourceOperationResult result, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(new
            {
                result.Success,
                result.DryRun,
                result.FailureKind,
                result.Message,
                resource = result.Resource is null ? null : new { result.Resource.ResourceId, result.Resource.Name, result.Resource.Destination, result.Resource.Protocol, result.Resource.Port, result.Resource.PortEnd, result.Resource.Enabled },
                issues = result.Issues.Select(i => i.ToString())
            });
        }
        else
        {
            Console.WriteLine(result.Message);
            if (result.Resource is not null)
            {
                Console.WriteLine($"  ResourceId: {result.Resource.ResourceId}, Destination: {result.Resource.Destination}, Enabled: {result.Resource.Enabled}");
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

    private static void PrintResourceList(IReadOnlyList<ProtectedResource> resources, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(resources.Select(r => new
            {
                r.ResourceId, r.Name, r.Description, r.Destination, r.Protocol, r.Port, r.PortEnd, r.Enabled, r.CreatedAtUtc, r.UpdatedAtUtc
            }));
            return;
        }

        if (resources.Count == 0)
        {
            Console.WriteLine("No resources registered.");
            return;
        }

        foreach (var r in resources)
        {
            var portDisplay = r.PortEnd is { } end ? $"{r.Port}-{end}" : r.Port.ToString();
            Console.WriteLine($"{r.ResourceId,-22} {(r.Enabled ? "Enabled " : "Disabled")} {r.Destination,-18} {r.Protocol,-4} {portDisplay,-10} {r.Name}");
        }
    }
}
