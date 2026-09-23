using System.Text;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.WireGuard;

public sealed class WireGuardConfigGenerator : IWireGuardConfigGenerator
{
    private readonly IConfigurationValidator _validator;
    private readonly ILogger<WireGuardConfigGenerator> _logger;

    public WireGuardConfigGenerator(IConfigurationValidator validator, ILogger<WireGuardConfigGenerator> logger)
    {
        _validator = validator;
        _logger = logger;
    }

    public async Task<ConfigGenerationResult> GenerateAsync(GatewayConfiguration configuration, IReadOnlyList<Peer> effectivePeers, ConfigGenerationOptions options, CancellationToken cancellationToken = default)
    {
        // Rule: "產生設定前先驗證設定" (docs/architecture.md 第六節) - never render/write a
        // configuration that would fail SecureTunnel's own safety checks.
        var validation = _validator.Validate(configuration);
        ValidatePeerSet(effectivePeers, validation);
        var rendered = Render(configuration, effectivePeers, redactPrivateKey: true);

        if (!validation.IsValid)
        {
            return new ConfigGenerationResult
            {
                Success = false,
                DryRun = options.DryRun,
                RenderedForReview = rendered,
                ValidationIssues = validation.Issues
            };
        }

        var outputPath = options.OutputPath ?? DefaultOutputPath(configuration);

        if (options.DryRun)
        {
            return new ConfigGenerationResult
            {
                Success = true,
                DryRun = true,
                RenderedForReview = rendered,
                ValidationIssues = validation.Issues
            };
        }

        if (File.Exists(outputPath) && !options.Force)
        {
            var issues = new List<ValidationIssue>(validation.Issues)
            {
                new("output.path", ValidationSeverity.Error,
                    $"'{outputPath}' already exists. Refusing to overwrite the active WireGuard configuration.",
                    "Re-run with --force, or use the Configuration Apply/Rollback flow (Phase 5) instead of writing directly.")
            };

            return new ConfigGenerationResult
            {
                Success = false,
                DryRun = false,
                RenderedForReview = rendered,
                ValidationIssues = issues
            };
        }

        try
        {
            var directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var fullContent = Render(configuration, effectivePeers, redactPrivateKey: false);
            await File.WriteAllTextAsync(outputPath, fullContent, cancellationToken);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(outputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            else
            {
                _logger.LogWarning("Running on Windows: cannot set Unix owner-only permissions on {Path}.", outputPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write WireGuard configuration to {Path}", outputPath);
            var issues = new List<ValidationIssue>(validation.Issues)
            {
                new("output.path", ValidationSeverity.Error, $"Failed to write configuration file: {ex.Message}")
            };
            return new ConfigGenerationResult
            {
                Success = false,
                DryRun = false,
                RenderedForReview = rendered,
                ValidationIssues = issues
            };
        }

        _logger.LogInformation("Wrote WireGuard configuration to {Path}", outputPath);

        return new ConfigGenerationResult
        {
            Success = true,
            DryRun = false,
            WrittenPath = outputPath,
            RenderedForReview = rendered,
            ValidationIssues = validation.Issues
        };
    }

    /// <summary>
    /// Renders the [Interface] section followed by one [Peer] block per entry in
    /// <paramref name="peers"/>. When <paramref name="redactPrivateKey"/> is true (always
    /// the case for anything returned to a caller for display/logging), the PrivateKey
    /// line shows a reference to the key file instead of its content. Only the file
    /// actually written to disk (never returned as a string) contains the real key.
    /// Peer public keys are not secret and are always rendered in full.
    /// </summary>
    private string Render(GatewayConfiguration config, IReadOnlyList<Peer> peers, bool redactPrivateKey)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Managed by SecureTunnel Gateway Agent. Do not edit peers manually;");
        sb.AppendLine("# use `securetunnel-gateway peer add|disable|remove` (Phase 3).");
        sb.AppendLine("[Interface]");
        sb.AppendLine($"Address = {config.Network.GatewayVpnAddress}/{CidrPrefixOrDefault(config.Network.VpnCidr)}");
        sb.AppendLine($"ListenPort = {config.WireGuard.ListenPort}");

        var privateKeyLine = redactPrivateKey
            ? $"PrivateKey = <loaded from {config.WireGuard.PrivateKeyPath}>"
            : $"PrivateKey = {ReadPrivateKeyOrThrow(config.WireGuard.PrivateKeyPath)}";
        sb.AppendLine(privateKeyLine);

        sb.AppendLine($"SaveConfig = {(config.WireGuard.SaveConfig ? "true" : "false")}");

        if (peers.Count == 0)
        {
            sb.AppendLine();
            sb.AppendLine("# No Active peers yet. Use `securetunnel-gateway peer add` to register one.");
            return sb.ToString();
        }

        foreach (var peer in peers.OrderBy(p => p.PeerId, StringComparer.Ordinal))
        {
            sb.AppendLine();
            sb.AppendLine($"# Peer: {peer.Name} ({peer.PeerId})");
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {peer.PublicKey}");
            sb.AppendLine($"AllowedIPs = {string.Join(", ", peer.AllowedIps)}");
            if (peer.PersistentKeepaliveSeconds is { } keepalive)
            {
                sb.AppendLine($"PersistentKeepalive = {keepalive}");
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Defense-in-depth: re-checks the peer set handed to us for the invariants
    /// docs/architecture.md 第七節 requires of the *effective* server configuration
    /// (unique public keys, unique AllowedIPs, all Active). Primary enforcement lives in
    /// Peers/PeerService and Peers/JsonFilePeerRepository; this catches the case where a
    /// caller passes an inconsistent list directly.
    /// </summary>
    private static void ValidatePeerSet(IReadOnlyList<Peer> peers, ValidationResult validation)
    {
        var nonActive = peers.Where(p => p.Status != PeerStatus.Active).ToList();
        foreach (var peer in nonActive)
        {
            validation.AddError("peers", $"Peer '{peer.PeerId}' has status {peer.Status}, but only Active peers may appear in the effective server configuration.");
        }

        var duplicateKeys = peers.GroupBy(p => p.PublicKey, StringComparer.Ordinal).Where(g => g.Count() > 1);
        foreach (var group in duplicateKeys)
        {
            validation.AddError("peers", $"Duplicate public key shared by peers: {string.Join(", ", group.Select(p => p.PeerId))}.");
        }

        var seenAllowedIps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var peer in peers)
        {
            foreach (var allowedIp in peer.AllowedIps)
            {
                if (!seenAllowedIps.Add(allowedIp))
                {
                    validation.AddError("peers", $"AllowedIP '{allowedIp}' on peer '{peer.PeerId}' is already assigned to another peer.");
                }
            }
        }
    }

    private static string ReadPrivateKeyOrThrow(string privateKeyPath)
    {
        if (!File.Exists(privateKeyPath))
        {
            throw new FileNotFoundException(
                $"Server private key not found at '{privateKeyPath}'. Generate it first with " +
                "`securetunnel-gateway wireguard generate-keys` (Phase 2.5).", privateKeyPath);
        }

        return File.ReadAllText(privateKeyPath).Trim();
    }

    private static string CidrPrefixOrDefault(string vpnCidr)
    {
        var parts = vpnCidr.Split('/');
        return parts.Length == 2 ? parts[1] : "24";
    }

    private static string DefaultOutputPath(GatewayConfiguration config) =>
        $"/etc/wireguard/{config.WireGuard.InterfaceName}.conf";
}
