using System.Text;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class FirewallRuleGenerator : IFirewallRuleGenerator
{
    private readonly ILogger<FirewallRuleGenerator> _logger;

    public FirewallRuleGenerator(ILogger<FirewallRuleGenerator> logger)
    {
        _logger = logger;
    }

    public Task<FirewallGenerationResult> GenerateAsync(
        GatewayConfiguration configuration,
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        FirewallGenerationOptions options,
        CancellationToken cancellationToken = default)
    {
        var validation = new ValidationResult();
        var effectiveRules = ComputeEffectiveRules(peers, resources, policies, validation);
        var rendered = Render(configuration, effectiveRules);

        if (!validation.IsValid)
        {
            return Task.FromResult(new FirewallGenerationResult
            {
                Success = false,
                DryRun = options.DryRun,
                RenderedForReview = rendered,
                ValidationIssues = validation.Issues,
                EffectiveRules = effectiveRules
            });
        }

        var outputPath = options.OutputPath ?? configuration.FirewallRulesetPath;

        if (options.DryRun)
        {
            return Task.FromResult(new FirewallGenerationResult
            {
                Success = true,
                DryRun = true,
                RenderedForReview = rendered,
                ValidationIssues = validation.Issues,
                EffectiveRules = effectiveRules
            });
        }

        if (File.Exists(outputPath) && !options.Force)
        {
            var issues = new List<ValidationIssue>(validation.Issues)
            {
                new("output.path", ValidationSeverity.Error,
                    $"'{outputPath}' already exists. Refusing to overwrite the active firewall ruleset.",
                    "Re-run with --force, or use the Configuration Apply flow instead of writing directly.")
            };
            return Task.FromResult(new FirewallGenerationResult
            {
                Success = false,
                DryRun = false,
                RenderedForReview = rendered,
                ValidationIssues = issues,
                EffectiveRules = effectiveRules
            });
        }

        try
        {
            var directory = Path.GetDirectoryName(outputPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(outputPath, rendered);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(outputPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write firewall ruleset to {Path}", outputPath);
            var issues = new List<ValidationIssue>(validation.Issues)
            {
                new("output.path", ValidationSeverity.Error, $"Failed to write ruleset file: {ex.Message}")
            };
            return Task.FromResult(new FirewallGenerationResult
            {
                Success = false,
                DryRun = false,
                RenderedForReview = rendered,
                ValidationIssues = issues,
                EffectiveRules = effectiveRules
            });
        }

        _logger.LogInformation("Wrote firewall ruleset ({RuleCount} effective rule(s)) to {Path}", effectiveRules.Count, outputPath);

        return Task.FromResult(new FirewallGenerationResult
        {
            Success = true,
            DryRun = false,
            WrittenPath = outputPath,
            RenderedForReview = rendered,
            ValidationIssues = validation.Issues,
            EffectiveRules = effectiveRules
        });
    }

    /// <summary>
    /// Filters to Active Peer + Enabled Resource + Enabled Policy (see docs/firewall-model.md
    /// 第三節 for why non-matching combinations are silently excluded rather than treated as
    /// errors), then defensively re-checks for duplicate/conflicting combinations - primary
    /// enforcement is Firewall/JsonFilePolicyRepository's duplicate-permission check, this is
    /// defense-in-depth for callers that construct a list directly (see
    /// WireGuard/WireGuardConfigGenerator.ValidatePeerSet for the same pattern).
    /// </summary>
    private static List<EffectiveAccessRule> ComputeEffectiveRules(
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        ValidationResult validation)
    {
        var activePeers = peers.Where(p => p.Status == PeerStatus.Active).ToDictionary(p => p.PeerId, StringComparer.Ordinal);
        var enabledResources = resources.Where(r => r.Enabled).ToDictionary(r => r.ResourceId, StringComparer.Ordinal);

        var rules = new List<EffectiveAccessRule>();
        foreach (var policy in policies)
        {
            if (!policy.Enabled)
            {
                continue;
            }

            if (!activePeers.TryGetValue(policy.PeerId, out var peer))
            {
                continue; // unknown or non-Active peer: excluded, not an error (see docs/firewall-model.md)
            }

            if (!enabledResources.TryGetValue(policy.ResourceId, out var resource))
            {
                continue; // unknown or disabled resource: excluded, not an error
            }

            rules.Add(new EffectiveAccessRule(policy.RuleId, peer.PeerId, peer.AssignedVpnIp, resource.ResourceId, resource.Destination, resource.Protocol, resource.Port, resource.PortEnd));
        }

        // Deterministic order: never depend on registry file order or dictionary iteration order.
        rules.Sort((a, b) =>
        {
            var cmp = string.CompareOrdinal(a.PeerVpnIp, b.PeerVpnIp);
            if (cmp != 0) return cmp;
            cmp = string.CompareOrdinal(a.Destination, b.Destination);
            if (cmp != 0) return cmp;
            return a.Port.CompareTo(b.Port);
        });

        var seen = new HashSet<(string, string, Protocol, int, int?)>();
        foreach (var rule in rules)
        {
            var key = (rule.PeerVpnIp, rule.Destination, rule.Protocol, rule.Port, rule.PortEnd);
            if (!seen.Add(key))
            {
                validation.AddError("policies", $"Duplicate effective rule for peer VPN IP {rule.PeerVpnIp} -> {rule.Destination} {rule.Protocol}/{rule.Port} (rule '{rule.RuleId}').");
            }
        }

        return rules;
    }

    private static string Render(GatewayConfiguration config, IReadOnlyList<EffectiveAccessRule> rules)
    {
        var sb = new StringBuilder();
        sb.AppendLine("#!/usr/sbin/nft -f");
        sb.AppendLine("# Managed by SecureTunnel Gateway Agent (Phase 4). Do not edit manually;");
        sb.AppendLine("# use `securetunnel-gateway resource|policy|firewall` commands and regenerate.");
        sb.AppendLine("# Table ownership: SecureTunnel Gateway owns ONLY `table inet securetunnel`.");
        sb.AppendLine("# It never touches any other nftables table on this host.");
        sb.AppendLine();
        sb.AppendLine("table inet securetunnel {");
        sb.AppendLine("    chain forward {");
        sb.AppendLine("        type filter hook forward priority 0; policy drop;");
        sb.AppendLine();
        sb.AppendLine("        # Return traffic for connections already permitted below.");
        sb.AppendLine("        ct state established,related accept");
        sb.AppendLine();
        sb.AppendLine("        # VPN Peer -> Protected Resource authorization decision. This chain is");
        sb.AppendLine("        # evaluated on the ORIGINAL (pre-NAT) VPN source IP: the postrouting NAT");
        sb.AppendLine("        # chain below runs at hook postrouting, which netfilter always processes");
        sb.AppendLine("        # AFTER the forward hook - see docs/firewall-model.md \"NAT Packet Flow\".");
        sb.AppendLine("        jump securetunnel_vpn_access");
        sb.AppendLine("        # No rule above matched -> falls through to this chain's `policy drop`.");
        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    chain securetunnel_vpn_access {");

        if (rules.Count == 0)
        {
            sb.AppendLine("        # No effective rules (no Active peer has an enabled policy to an enabled");
            sb.AppendLine("        # resource). Everything falls through to the forward chain's default deny.");
        }
        else
        {
            foreach (var rule in rules)
            {
                sb.AppendLine($"        # peer:{rule.PeerId} -> resource:{rule.ResourceId} (rule:{rule.RuleId})");
                sb.AppendLine($"        {RenderMatch(rule)} accept");
            }
        }

        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    chain postrouting {");
        sb.AppendLine("        type nat hook postrouting priority 100;");
        sb.AppendLine();

        var protectedNetworks = config.Network.ProtectedNetworks;
        if (!string.Equals(config.Routing.Mode, "nat", StringComparison.OrdinalIgnoreCase) || protectedNetworks.Count == 0)
        {
            sb.AppendLine("        # No NAT rules generated (routing.mode is not \"nat\", or no protected");
            sb.AppendLine("        # networks are configured).");
        }
        else
        {
            sb.AppendLine("        # SNAT/MASQUERADE scoped to VPN -> protected network only - never a");
            sb.AppendLine("        # blanket masquerade of all forwarded traffic. See docs/network-topology.md.");
            foreach (var net in protectedNetworks)
            {
                sb.AppendLine($"        ip saddr {config.Network.VpnCidr} ip daddr {net.Cidr} masquerade");
            }
        }

        sb.AppendLine("    }");
        sb.AppendLine("}");

        return sb.ToString();
    }

    private static string RenderMatch(EffectiveAccessRule rule)
    {
        var proto = rule.Protocol == Protocol.Tcp ? "tcp" : "udp";
        var dport = rule.PortEnd is { } end ? $"{rule.Port}-{end}" : rule.Port.ToString();
        return $"ip saddr {rule.PeerVpnIp} ip daddr {rule.Destination} {proto} dport {dport}";
    }
}
