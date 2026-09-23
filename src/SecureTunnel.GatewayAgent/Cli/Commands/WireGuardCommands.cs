using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.WireGuard;

namespace SecureTunnel.GatewayAgent.Cli.Commands;

/// <summary>
/// wireguard status|show|generate|generate-keys|start|stop|restart.
/// </summary>
internal static class WireGuardCommands
{
    internal static Command Build(IServiceProvider services)
    {
        var wgCmd = new Command("wireguard", "WireGuard interface operations");

        var interfaceOption = new Option<string?>("--interface")
        {
            Description = "Override the interface name from gateway.yaml"
        };

        var statusCmd = new Command("status", "Show whether the WireGuard interface is up");
        statusCmd.Options.Add(CommonOptions.Config);
        statusCmd.Options.Add(interfaceOption);
        statusCmd.Options.Add(CommonOptions.Json);
        statusCmd.SetAction((parseResult, ct) => RunInterfaceQuery(services, parseResult, interfaceOption,
            async (wg, iface, ct2) =>
            {
                var status = await wg.GetStatusAsync(iface, ct2);
                return (status.Message, status.State != WireGuardInterfaceState.Unknown, (object)status);
            }, ct));

        var showCmd = new Command("show", "Show `wg show` output for the interface (BLOCKED if wg is unavailable)");
        showCmd.Options.Add(CommonOptions.Config);
        showCmd.Options.Add(interfaceOption);
        showCmd.Options.Add(CommonOptions.Json);
        showCmd.SetAction((parseResult, ct) => RunInterfaceQuery(services, parseResult, interfaceOption,
            async (wg, iface, ct2) =>
            {
                var output = await wg.ShowAsync(iface, ct2);
                return (output, !output.StartsWith("BLOCKED"), (object)new { output });
            }, ct));

        var generateCmd = new Command("generate", "Render the WireGuard interface configuration (alias of `config generate`)");
        generateCmd.Options.Add(CommonOptions.Config);
        generateCmd.Options.Add(CommonOptions.Output);
        generateCmd.Options.Add(CommonOptions.DryRun);
        generateCmd.Options.Add(CommonOptions.Force);
        generateCmd.Options.Add(CommonOptions.Json);
        generateCmd.SetAction((parseResult, ct) => GenerateWireGuardConfigAsync(services, parseResult, ct));

        var generateKeysCmd = new Command("generate-keys", "Generate a new server key pair (refuses to overwrite an existing key unless --force)");
        generateKeysCmd.Options.Add(CommonOptions.Config);
        generateKeysCmd.Options.Add(CommonOptions.DryRun);
        generateKeysCmd.Options.Add(CommonOptions.Force);
        generateKeysCmd.Options.Add(CommonOptions.Yes);
        generateKeysCmd.Options.Add(CommonOptions.Json);
        generateKeysCmd.SetAction(async (parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config)!;
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var force = parseResult.GetValue(CommonOptions.Force);
            var yes = parseResult.GetValue(CommonOptions.Yes);
            var json = parseResult.GetValue(CommonOptions.Json);

            using var scope = services.CreateScope(dryRun);
            var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
            var keyService = scope.ServiceProvider.GetRequiredService<IKeyManagementService>();

            GatewayConfiguration config;
            try
            {
                config = loader.Load(configPath);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ERROR] Failed to load '{configPath}': {ex.Message}");
                return ExitCodes.ValidationFailure;
            }

            if (force && !dryRun && !yes)
            {
                Console.Error.WriteLine(
                    "[ERROR] --force would replace an existing server key, which breaks connectivity for every " +
                    "existing peer. Re-run with --yes to confirm this destructive action, or without --force to keep the existing key.");
                return ExitCodes.GeneralFailure;
            }

            var result = await keyService.GenerateServerKeyPairAsync(
                config.WireGuard.PrivateKeyPath,
                config.WireGuard.PublicKeyPath,
                new KeyGenerationOptions { DryRun = dryRun, Force = force },
                ct);

            if (json)
            {
                OutputFormat.PrintJson(new { result.Success, result.DryRun, result.PublicKey, result.PrivateKeyPath, result.PublicKeyPath, result.Message });
            }
            else
            {
                Console.WriteLine(result.Message);
                if (result.PublicKey is not null)
                {
                    Console.WriteLine($"Public key: {result.PublicKey}");
                }
            }

            return result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure;
        });

        var startCmd = BuildMutatingCommand("start", "Bring the WireGuard interface up (wg-quick up)", services, interfaceOption, (wg, iface, ct2) => wg.StartAsync(iface, ct2));
        var stopCmd = BuildMutatingCommand("stop", "Bring the WireGuard interface down (wg-quick down)", services, interfaceOption, (wg, iface, ct2) => wg.StopAsync(iface, ct2));
        var restartCmd = BuildMutatingCommand("restart", "Restart the WireGuard interface", services, interfaceOption, (wg, iface, ct2) => wg.RestartAsync(iface, ct2));

        wgCmd.Subcommands.Add(statusCmd);
        wgCmd.Subcommands.Add(showCmd);
        wgCmd.Subcommands.Add(generateCmd);
        wgCmd.Subcommands.Add(generateKeysCmd);
        wgCmd.Subcommands.Add(startCmd);
        wgCmd.Subcommands.Add(stopCmd);
        wgCmd.Subcommands.Add(restartCmd);

        return wgCmd;
    }

    /// <summary>
    /// Shared by `wireguard generate` and the legacy `config generate` alias.
    /// </summary>
    internal static async Task<int> GenerateWireGuardConfigAsync(IServiceProvider services, ParseResult parseResult, CancellationToken ct)
    {
        var configPath = parseResult.GetValue(CommonOptions.Config)!;
        var outputPath = parseResult.GetValue(CommonOptions.Output);
        var dryRun = parseResult.GetValue(CommonOptions.DryRun);
        var force = parseResult.GetValue(CommonOptions.Force);
        var json = parseResult.GetValue(CommonOptions.Json);

        using var scope = services.CreateScope(dryRun);
        var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
        var generator = scope.ServiceProvider.GetRequiredService<IWireGuardConfigGenerator>();
        var peerService = scope.ServiceProvider.GetRequiredService<IPeerService>();

        GatewayConfiguration config;
        try
        {
            config = loader.Load(configPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] Failed to load '{configPath}': {ex.Message}");
            return ExitCodes.ValidationFailure;
        }

        IReadOnlyList<Peer> effectivePeers;
        try
        {
            effectivePeers = await peerService.GetEffectivePeersAsync(config, ct);
        }
        catch (PeerRegistryCorruptException ex)
        {
            Console.Error.WriteLine($"[ERROR] Peer registry error: {ex.Message}");
            return ExitCodes.ValidationFailure;
        }

        var result = await generator.GenerateAsync(config, effectivePeers, new ConfigGenerationOptions
        {
            DryRun = dryRun,
            Force = force,
            OutputPath = outputPath
        }, ct);

        if (json)
        {
            OutputFormat.PrintJson(new
            {
                result.Success,
                result.DryRun,
                result.WrittenPath,
                rendered = result.RenderedForReview,
                issues = result.ValidationIssues.Select(i => i.ToString())
            });
        }
        else
        {
            Console.WriteLine("--- Rendered configuration (for review; PrivateKey is always redacted here) ---");
            Console.WriteLine(result.RenderedForReview);
            foreach (var issue in result.ValidationIssues)
            {
                Console.WriteLine(issue.ToString());
            }

            if (result.Success)
            {
                Console.WriteLine(result.DryRun
                    ? "[DRY-RUN] No file was written."
                    : $"Written to: {result.WrittenPath}");
            }
            else
            {
                Console.WriteLine("Result: FAILED (see issues above)");
            }
        }

        return result.Success ? ExitCodes.Success : ExitCodes.ValidationFailure;
    }

    private static Command BuildMutatingCommand(
        string name,
        string description,
        IServiceProvider services,
        Option<string?> interfaceOption,
        Func<IWireGuardService, string, CancellationToken, Task<CommandExecutionResult>> action)
    {
        var cmd = new Command(name, description);
        cmd.Options.Add(CommonOptions.Config);
        cmd.Options.Add(interfaceOption);
        cmd.Options.Add(CommonOptions.DryRun);
        cmd.Options.Add(CommonOptions.Yes);
        cmd.Options.Add(CommonOptions.Json);
        cmd.SetAction(async (parseResult, ct) =>
        {
            var configPath = parseResult.GetValue(CommonOptions.Config)!;
            var ifaceOverride = parseResult.GetValue(interfaceOption);
            var dryRun = parseResult.GetValue(CommonOptions.DryRun);
            var yes = parseResult.GetValue(CommonOptions.Yes);
            var json = parseResult.GetValue(CommonOptions.Json);

            if (!dryRun && !yes)
            {
                Console.Error.WriteLine(
                    $"[ERROR] '{name}' changes the running WireGuard interface. Re-run with --yes to confirm " +
                    "(or --dry-run to preview without changing anything).");
                return ExitCodes.GeneralFailure;
            }

            using var scope = services.CreateScope(dryRun);
            var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
            var wg = scope.ServiceProvider.GetRequiredService<IWireGuardService>();

            string iface;
            try
            {
                iface = ifaceOverride ?? loader.Load(configPath).WireGuard.InterfaceName;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[ERROR] Failed to load '{configPath}': {ex.Message}");
                return ExitCodes.ValidationFailure;
            }

            var result = await action(wg, iface, ct);
            var blocked = result.ExitCode == -1;

            if (json)
            {
                OutputFormat.PrintJson(new
                {
                    blocked,
                    result.Success,
                    result.ExitCode,
                    stdout = result.StandardOutput,
                    stderr = result.StandardError
                });
            }
            else if (blocked)
            {
                Console.WriteLine($"BLOCKED: {result.StandardError}");
            }
            else
            {
                Console.WriteLine(result.Success ? $"OK: {name} succeeded." : $"FAILED ({result.ExitCode}): {result.StandardError}");
            }

            return blocked ? ExitCodes.GeneralFailure : (result.Success ? ExitCodes.Success : ExitCodes.GeneralFailure);
        });
        return cmd;
    }

    private static async Task<int> RunInterfaceQuery(
        IServiceProvider services,
        ParseResult parseResult,
        Option<string?> interfaceOption,
        Func<IWireGuardService, string, CancellationToken, Task<(string Message, bool Ok, object Payload)>> query,
        CancellationToken ct)
    {
        var configPath = parseResult.GetValue(CommonOptions.Config)!;
        var ifaceOverride = parseResult.GetValue(interfaceOption);
        var json = parseResult.GetValue(CommonOptions.Json);

        using var scope = services.CreateScope();
        var loader = scope.ServiceProvider.GetRequiredService<IConfigurationLoader>();
        var wg = scope.ServiceProvider.GetRequiredService<IWireGuardService>();

        string iface;
        try
        {
            iface = ifaceOverride ?? loader.Load(configPath).WireGuard.InterfaceName;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[ERROR] Failed to load '{configPath}': {ex.Message}");
            return ExitCodes.ValidationFailure;
        }

        var (message, ok, payload) = await query(wg, iface, ct);

        if (json)
        {
            OutputFormat.PrintJson(payload);
        }
        else
        {
            Console.WriteLine(message);
        }

        return ok ? ExitCodes.Success : ExitCodes.GeneralFailure;
    }
}
