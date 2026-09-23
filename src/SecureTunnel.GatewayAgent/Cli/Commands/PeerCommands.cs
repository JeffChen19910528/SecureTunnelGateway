using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.WireGuard;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// peer list|show|add|enable|disable|revoke|remove|status|allocate-ip|config.
/// </summary>
internal static class PeerCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var idOption = new Option<string>("--id") { Description = "Peer id (as shown by `peer list`)", Required = true };
        var nameOption = new Option<string>("--name") { Description = "Human-readable peer name", Required = true };
        var publicKeyOption = new Option<string>("--public-key") { Description = "Client WireGuard public key (base64); the Gateway never accepts a private key" };
        var descriptionOption = new Option<string?>("--description") { Description = "Optional free-text description" };
        var vpnIpOption = new Option<string?>("--vpn-ip") { Description = "Explicit VPN IP to request/check, instead of automatic allocation" };

        var peerCmd = new Command("peer", "Peer (VPN Client) registration and lifecycle management");

        var listCmd = new Command("list", "List all registered peers (all statuses)");
        listCmd.Options.Add(CommonOptions.Config);
        listCmd.Options.Add(CommonOptions.Json);
        listCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            try
            {
                var peers = await peerService.ListAsync(config, ct);
                PrintPeerList(peers, parseResult.GetValue(CommonOptions.Json));
                return ExitCodes.Success;
            }
            catch (PeerRegistryCorruptException ex)
            {
                Console.Error.WriteLine($"[ERROR] Peer registry error: {ex.Message}");
                return ExitCodes.GeneralFailure;
            }
        });

        var showCmd = new Command("show", "Show a single peer's metadata (never its private key - the Gateway never has one)");
        showCmd.Options.Add(CommonOptions.Config);
        showCmd.Options.Add(idOption);
        showCmd.Options.Add(CommonOptions.Json);
        showCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var peer = await peerService.GetAsync(config, parseResult.GetValue(idOption)!, ct);
            if (peer is null)
            {
                Console.Error.WriteLine("[ERROR] Peer not found.");
                return ExitCodes.GeneralFailure;
            }

            PrintPeerList(new[] { peer }, parseResult.GetValue(CommonOptions.Json));
            return ExitCodes.Success;
        });

        var addCmd = new Command("add", "Register a new peer (requires --yes or --dry-run: this grants VPN access)");
        addCmd.Options.Add(CommonOptions.Config);
        addCmd.Options.Add(nameOption);
        addCmd.Options.Add(publicKeyOption);
        addCmd.Options.Add(descriptionOption);
        addCmd.Options.Add(vpnIpOption);
        addCmd.Options.Add(CommonOptions.DryRun);
        addCmd.Options.Add(CommonOptions.Yes);
        addCmd.Options.Add(CommonOptions.Json);
        addCmd.SetAction(async (parseResult, ct) =>
        {
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var json = parseResult.GetValue(CommonOptions.Json);
            if (!dryRun && !parseResult.GetValue(CommonOptions.Yes))
            {
                Console.Error.WriteLine("[ERROR] 'peer add' grants VPN access. Re-run with --yes to confirm (or --dry-run to preview).");
                return ExitCodes.GeneralFailure;
            }

            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, json);

            var publicKey = parseResult.GetValue(publicKeyOption);
            if (string.IsNullOrWhiteSpace(publicKey))
            {
                Console.Error.WriteLine("[ERROR] --public-key is required. The Gateway never generates a Client key pair on the operator's behalf - generate one on the Client with `wg genkey` / `wg pubkey` and pass the public key here.");
                return ExitCodes.ValidationFailure;
            }

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var result = await peerService.AddAsync(config, parseResult.GetValue(nameOption)!, publicKey,
                parseResult.GetValue(descriptionOption), parseResult.GetValue(vpnIpOption), dryRun, ct);

            return ReportPeerResult(result, json);
        });

        var enableCmd = BuildPeerTransitionCommand("enable", "Re-activate a Disabled peer (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.EnableAsync(config, id, dryRun, ct));
        var disableCmd = BuildPeerTransitionCommand("disable", "Temporarily deactivate a peer, keeping its identity/VPN IP (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.DisableAsync(config, id, dryRun, ct));
        var revokeCmd = BuildPeerTransitionCommand("revoke", "Permanently invalidate a peer's access; its public key can never be re-added (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.RevokeAsync(config, id, dryRun, ct));
        var removeCmd = BuildPeerTransitionCommand("remove", "Archive a peer (soft-delete; audit metadata retained) (requires --yes or --dry-run)", services, idOption,
            (svc, config, id, dryRun, ct) => svc.RemoveAsync(config, id, dryRun, ct));

        var statusCmd = new Command("status", "Show a peer's stored status plus a best-effort live WireGuard cross-reference");
        statusCmd.Options.Add(CommonOptions.Config);
        statusCmd.Options.Add(idOption);
        statusCmd.Options.Add(CommonOptions.Json);
        statusCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var wg = scope.ServiceProvider.GetRequiredService<IWireGuardService>();

            var peer = await peerService.GetAsync(config, parseResult.GetValue(idOption)!, ct);
            if (peer is null)
            {
                Console.Error.WriteLine("[ERROR] Peer not found.");
                return ExitCodes.GeneralFailure;
            }

            var wgShow = await wg.ShowAsync(config.WireGuard.InterfaceName, ct);
            var liveLine = wgShow.Contains(peer.PublicKey, StringComparison.Ordinal)
                ? "Found in live `wg show` output (see raw output for handshake/transfer detail)."
                : wgShow.StartsWith("BLOCKED", StringComparison.Ordinal)
                    ? "Live WireGuard status unavailable (BLOCKED - see message)."
                    : "Not present in live `wg show` output (interface may be down, or peer not yet applied - see `wireguard start`/`config generate`).";

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { peer.PeerId, peer.Name, peer.Status, peer.AssignedVpnIp, live = liveLine, wireGuardRaw = wgShow });
            }
            else
            {
                Console.WriteLine($"Peer '{peer.Name}' ({peer.PeerId}): stored status = {peer.Status}, VPN IP = {peer.AssignedVpnIp}");
                Console.WriteLine($"Live WireGuard: {liveLine}");
            }

            return ExitCodes.Success;
        });

        var allocateIpCmd = new Command("allocate-ip", "Preview the next automatically-allocated VPN IP, or check whether a specific IP is available (does not persist anything)");
        allocateIpCmd.Options.Add(CommonOptions.Config);
        allocateIpCmd.Options.Add(vpnIpOption);
        allocateIpCmd.Options.Add(CommonOptions.Json);
        allocateIpCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var allocator = scope.ServiceProvider.GetRequiredService<IVpnIpAllocator>();

            IReadOnlyList<Peer> peers;
            try
            {
                peers = await peerService.ListAsync(config, ct);
            }
            catch (PeerRegistryCorruptException ex)
            {
                Console.Error.WriteLine($"[ERROR] Peer registry error: {ex.Message}");
                return ExitCodes.GeneralFailure;
            }

            var result = allocator.Allocate(config, peers, parseResult.GetValue(vpnIpOption));

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { result.Success, result.AllocatedIp, result.Message });
            }
            else
            {
                Console.WriteLine(result.Message);
            }

            return result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });

        var configCmd = new Command("config", "Generate a Client configuration TEMPLATE for a peer (never a complete usable config - see docs/configuration-guide.md)");
        configCmd.Options.Add(CommonOptions.Config);
        configCmd.Options.Add(idOption);
        configCmd.Options.Add(CommonOptions.Output);
        configCmd.Options.Add(CommonOptions.Force);
        configCmd.Options.Add(CommonOptions.Json);
        configCmd.SetAction(async (parseResult, ct) =>
        {
            var (config, error) = await CommandHelpers.LoadConfigAsync(services, parseResult, ct);
            if (config is null) return CommandHelpers.ReportLoadError(error!, parseResult.GetValue(CommonOptions.Json));

            using var scope = services.CreateScope();
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var templateGenerator = scope.ServiceProvider.GetRequiredService<IClientConfigTemplateGenerator>();

            var peer = await peerService.GetAsync(config, parseResult.GetValue(idOption)!, ct);
            if (peer is null)
            {
                Console.Error.WriteLine("[ERROR] Peer not found.");
                return ExitCodes.GeneralFailure;
            }

            var templateResult = await templateGenerator.GenerateAsync(config, peer, ct);
            if (!templateResult.Success)
            {
                Console.Error.WriteLine(templateResult.Message);
                return ExitCodes.GeneralFailure;
            }

            var outputPath = parseResult.GetValue(CommonOptions.Output);
            var force = parseResult.GetValue(CommonOptions.Force);
            string? writtenPath = null;

            if (!string.IsNullOrWhiteSpace(outputPath))
            {
                if (File.Exists(outputPath) && !force)
                {
                    Console.Error.WriteLine($"[ERROR] '{outputPath}' already exists. Re-run with --force to overwrite.");
                    return ExitCodes.GeneralFailure;
                }

                await File.WriteAllTextAsync(outputPath, templateResult.RenderedTemplate, ct);
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(outputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }
                writtenPath = outputPath;
            }

            if (parseResult.GetValue(CommonOptions.Json))
            {
                OutputFormat.PrintJson(new { templateResult.Success, templateResult.IsCompleteUsableConfig, writtenPath, template = templateResult.RenderedTemplate });
            }
            else
            {
                Console.WriteLine(templateResult.RenderedTemplate);
                Console.WriteLine(writtenPath is null ? "(not written to a file - pass --output <path> to save)" : $"Written to: {writtenPath}");
            }

            return ExitCodes.Success;
        });

        peerCmd.Subcommands.Add(listCmd);
        peerCmd.Subcommands.Add(showCmd);
        peerCmd.Subcommands.Add(addCmd);
        peerCmd.Subcommands.Add(enableCmd);
        peerCmd.Subcommands.Add(disableCmd);
        peerCmd.Subcommands.Add(revokeCmd);
        peerCmd.Subcommands.Add(removeCmd);
        peerCmd.Subcommands.Add(statusCmd);
        peerCmd.Subcommands.Add(allocateIpCmd);
        peerCmd.Subcommands.Add(configCmd);

        return peerCmd;
    }

    private static Command BuildPeerTransitionCommand(
        string name,
        string description,
        IServiceProvider services,
        Option<string> idOption,
        Func<IPeerService, GatewayConfiguration, string, bool, CancellationToken, Task<PeerOperationResult>> action)
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
            var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();
            var result = await action(peerService, config, parseResult.GetValue(idOption)!, dryRun, ct);

            return ReportPeerResult(result, json);
        });
        return cmd;
    }

    private static int ReportPeerResult(PeerOperationResult result, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(new
            {
                result.Success,
                result.DryRun,
                result.FailureKind,
                result.Message,
                peer = result.Peer is null ? null : new { result.Peer.PeerId, result.Peer.Name, result.Peer.Status, result.Peer.AssignedVpnIp, result.Peer.PublicKey },
                issues = result.Issues.Select(i => i.ToString())
            });
        }
        else
        {
            Console.WriteLine(result.Message);
            if (result.Peer is not null)
            {
                Console.WriteLine($"  PeerId: {result.Peer.PeerId}, Status: {result.Peer.Status}, VPN IP: {result.Peer.AssignedVpnIp}");
            }
        }

        if (!result.Success)
        {
            return result.FailureKind switch
            {
                PeerOperationFailureKind.ValidationFailed => ExitCodes.ValidationFailure,
                _ => ExitCodes.GeneralFailure
            };
        }

        return ExitCodes.Success;
    }

    private static void PrintPeerList(IReadOnlyList<Peer> peers, bool json)
    {
        if (json)
        {
            OutputFormat.PrintJson(peers.Select(p => new
            {
                p.PeerId,
                p.Name,
                p.Description,
                p.Status,
                p.AssignedVpnIp,
                p.PublicKey,
                p.CreatedAtUtc,
                p.UpdatedAtUtc,
                p.LastHandshakeAtUtc
            }));
            return;
        }

        if (peers.Count == 0)
        {
            Console.WriteLine("No peers registered.");
            return;
        }

        foreach (var p in peers)
        {
            Console.WriteLine($"{p.PeerId,-20} {p.Status,-10} {p.AssignedVpnIp,-16} {p.Name}");
        }
    }
}
