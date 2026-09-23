using System.Text.RegularExpressions;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Validation;

/// <summary>
/// Validates a <see cref="GatewayConfiguration"/> against the rules in
/// docs/configuration-guide.md and docs/security-model.md. This validator is the single
/// place responsible for refusing dangerous configurations (allow-all, non-deny firewall
/// policy, fail-closed disabled, unsupported routing mode, overlapping networks, etc.).
/// </summary>
public sealed class GatewayConfigurationValidator : IConfigurationValidator
{
    // Linux IFNAMSIZ is 16 bytes including the terminating NUL, so 15 usable characters.
    // Only allow characters that are safe to place in a command-line argument to `ip`/`wg-quick`.
    private static readonly Regex SafeInterfaceName = new("^[a-zA-Z0-9][a-zA-Z0-9_-]{0,14}$", RegexOptions.Compiled);

    // A small set of locations we refuse to treat as a "safe" place for a private key file.
    private static readonly string[] UnsafeKeyPathPrefixes =
    {
        "/tmp/", "/var/tmp/", "/dev/shm/"
    };

    public ValidationResult Validate(GatewayConfiguration configuration)
    {
        var result = new ValidationResult();

        ValidateInterfaceName(configuration, result);
        ValidateListenPort(configuration, result);
        ValidateNetwork(configuration, result);
        ValidatePrivateKeyPath(configuration, result);
        ValidateSecurity(configuration, result);
        ValidateRouting(configuration, result);
        ValidateProtectedNetworks(configuration, result);

        return result;
    }

    // Rules 1-2: InterfaceName not empty, no dangerous characters.
    private static void ValidateInterfaceName(GatewayConfiguration config, ValidationResult result)
    {
        var name = config.WireGuard.InterfaceName;
        if (string.IsNullOrWhiteSpace(name))
        {
            result.AddError("wireGuard.interfaceName", "Interface name must not be empty.",
                "Set wireGuard.interfaceName, e.g. \"wg-securetunnel\".");
            return;
        }

        if (!SafeInterfaceName.IsMatch(name))
        {
            result.AddError("wireGuard.interfaceName",
                $"Interface name '{name}' contains unsafe characters or exceeds 15 characters (Linux IFNAMSIZ limit).",
                "Use only letters, digits, '-' and '_', starting with a letter or digit, 1-15 characters.");
        }

        // Rule 20 (partial): interface name must not collide with the LAN interface name.
        if (!string.IsNullOrWhiteSpace(config.Network.LanInterface) &&
            string.Equals(name, config.Network.LanInterface, StringComparison.Ordinal))
        {
            result.AddError("wireGuard.interfaceName",
                $"wireGuard.interfaceName and network.lanInterface are both '{name}'.",
                "The VPN interface and the LAN-facing interface must be different devices.");
        }
    }

    // Rules 3, 10: ListenPort must be 1-65535.
    private static void ValidateListenPort(GatewayConfiguration config, ValidationResult result)
    {
        var port = config.WireGuard.ListenPort;
        if (port < 1 || port > 65535)
        {
            result.AddError("wireGuard.listenPort", $"Listen port {port} is out of range.",
                "Use a value between 1 and 65535 (WireGuard default is 51820).");
        }
    }

    // Rules 4-9: VPN CIDR format, gateway IP in CIDR, client pool in CIDR, gateway IP not in pool,
    // VPN CIDR not overlapping protected networks.
    private static void ValidateNetwork(GatewayConfiguration config, ValidationResult result)
    {
        var net = config.Network;

        if (!Ipv4NetworkUtils.TryParseCidr(net.VpnCidr, out var vpnNetwork, out var vpnPrefix))
        {
            result.AddError("network.vpnCidr", $"'{net.VpnCidr}' is not a valid IPv4 CIDR.",
                "Use a format like \"10.250.0.0/24\".");
            return; // Can't validate anything relative to an invalid CIDR.
        }

        if (!Ipv4NetworkUtils.TryParseIp(net.GatewayVpnAddress, out var gatewayIp))
        {
            result.AddError("network.gatewayVpnAddress", $"'{net.GatewayVpnAddress}' is not a valid IPv4 address.");
        }
        else if (!Ipv4NetworkUtils.IsAddressInCidr(gatewayIp, vpnNetwork, vpnPrefix))
        {
            result.AddError("network.gatewayVpnAddress",
                $"Gateway VPN address {net.GatewayVpnAddress} is not inside network.vpnCidr ({net.VpnCidr}).");
        }

        var poolStartOk = Ipv4NetworkUtils.TryParseIp(net.ClientAddressPoolStart, out var poolStart);
        var poolEndOk = Ipv4NetworkUtils.TryParseIp(net.ClientAddressPoolEnd, out var poolEnd);

        if (!poolStartOk)
        {
            result.AddError("network.clientAddressPoolStart", $"'{net.ClientAddressPoolStart}' is not a valid IPv4 address.");
        }

        if (!poolEndOk)
        {
            result.AddError("network.clientAddressPoolEnd", $"'{net.ClientAddressPoolEnd}' is not a valid IPv4 address.");
        }

        if (poolStartOk && poolEndOk)
        {
            if (poolStart > poolEnd)
            {
                result.AddError("network.clientAddressPool",
                    $"clientAddressPoolStart ({net.ClientAddressPoolStart}) is after clientAddressPoolEnd ({net.ClientAddressPoolEnd}).");
            }

            if (!Ipv4NetworkUtils.IsAddressInCidr(poolStart, vpnNetwork, vpnPrefix) ||
                !Ipv4NetworkUtils.IsAddressInCidr(poolEnd, vpnNetwork, vpnPrefix))
            {
                result.AddError("network.clientAddressPool",
                    $"Client address pool ({net.ClientAddressPoolStart}-{net.ClientAddressPoolEnd}) is not entirely inside network.vpnCidr ({net.VpnCidr}).");
            }

            // Rule 7: gateway IP must not fall inside the client pool range.
            if (Ipv4NetworkUtils.TryParseIp(net.GatewayVpnAddress, out var gwIp) &&
                gwIp >= poolStart && gwIp <= poolEnd)
            {
                result.AddError("network.gatewayVpnAddress",
                    $"Gateway VPN address {net.GatewayVpnAddress} falls inside the client address pool ({net.ClientAddressPoolStart}-{net.ClientAddressPoolEnd}).",
                    "Choose a gateway address outside the pool range, or shrink the pool.");
            }
        }

        // Rule 8: VPN CIDR must not overlap any protected network CIDR.
        foreach (var protectedNet in net.ProtectedNetworks)
        {
            if (!Ipv4NetworkUtils.TryParseCidr(protectedNet.Cidr, out var pNet, out var pPrefix))
            {
                continue; // reported separately in ValidateProtectedNetworks
            }

            if (Ipv4NetworkUtils.CidrsOverlap(vpnNetwork, vpnPrefix, pNet, pPrefix))
            {
                result.AddError("network.vpnCidr",
                    $"network.vpnCidr ({net.VpnCidr}) overlaps with protected network '{protectedNet.Name}' ({protectedNet.Cidr}).",
                    "Choose non-overlapping CIDR ranges for the VPN network and protected networks.");
            }
        }

        if (string.IsNullOrWhiteSpace(net.LanInterface))
        {
            result.AddError("network.lanInterface", "LAN interface must not be empty.",
                "Set network.lanInterface to the interface name facing the protected network(s).");
        }
    }

    // Rules 11-12: private key path not empty, not in an unsafe location.
    private static void ValidatePrivateKeyPath(GatewayConfiguration config, ValidationResult result)
    {
        var path = config.WireGuard.PrivateKeyPath;
        if (string.IsNullOrWhiteSpace(path))
        {
            result.AddError("wireGuard.privateKeyPath", "Private key path must not be empty.");
            return;
        }

        if (!Path.IsPathFullyQualified(path) && !path.StartsWith('/'))
        {
            result.AddError("wireGuard.privateKeyPath", $"'{path}' must be an absolute path.");
        }

        foreach (var unsafePrefix in UnsafeKeyPathPrefixes)
        {
            if (path.StartsWith(unsafePrefix, StringComparison.Ordinal))
            {
                result.AddError("wireGuard.privateKeyPath",
                    $"'{path}' is inside '{unsafePrefix}', which is a world-writable/temporary location and unsafe for a private key.",
                    "Store the private key under a directory such as /etc/securetunnel-gateway/keys with 0700/0600 permissions.");
            }
        }
    }

    // Rules 13-14, 18: firewall default policy must be deny, fail-closed must be true,
    // allow-unlisted-resources must be false.
    private static void ValidateSecurity(GatewayConfiguration config, ValidationResult result)
    {
        var sec = config.Security;

        if (!string.Equals(sec.FirewallDefaultPolicy, "deny", StringComparison.OrdinalIgnoreCase))
        {
            result.AddError("security.firewallDefaultPolicy",
                $"security.firewallDefaultPolicy is '{sec.FirewallDefaultPolicy}', but only 'deny' is allowed.",
                "Set security.firewallDefaultPolicy to \"deny\". SecureTunnel Gateway does not support a default-allow policy.");
        }

        if (!sec.FailClosed)
        {
            result.AddError("security.failClosed",
                "security.failClosed is false. SecureTunnel Gateway requires fail-closed behavior.",
                "Set security.failClosed to true.");
        }

        if (sec.AllowUnlistedResources)
        {
            result.AddError("security.allowUnlistedResources",
                "security.allowUnlistedResources is true, which would allow access to resources with no explicit rule.",
                "Set security.allowUnlistedResources to false and define explicit resource rules (see config/protected-resources.example.yaml).");
        }
    }

    // Rules 15-17: NAT mode consistency, routed mode rejected, IPv6 forwarding requires explicit ack.
    private static void ValidateRouting(GatewayConfiguration config, ValidationResult result)
    {
        var routing = config.Routing;
        var mode = routing.Mode?.Trim().ToLowerInvariant();

        switch (mode)
        {
            case "nat":
                if (!routing.NatEnabled)
                {
                    result.AddError("routing.natEnabled",
                        "routing.mode is 'nat' but routing.natEnabled is false.",
                        "Set routing.natEnabled to true, or change routing.mode.");
                }
                break;

            case "routed":
                result.AddError("routing.mode",
                    "routing.mode = \"routed\" is not supported in this release.",
                    "Use routing.mode = \"nat\" (see docs/network-topology.md, Routed Mode is a future enhancement).");
                break;

            default:
                result.AddError("routing.mode",
                    $"routing.mode '{routing.Mode}' is not recognized. Supported values: [\"nat\"] (\"routed\" is reserved for a future release).");
                break;
        }

        if (routing.EnableIpv6Forwarding && !routing.Ipv6PolicyAcknowledged)
        {
            result.AddError("routing.enableIpv6Forwarding",
                "routing.enableIpv6Forwarding is true but routing.ipv6PolicyAcknowledged is false.",
                "IPv6 forwarding must be explicitly acknowledged (routing.ipv6PolicyAcknowledged = true) to avoid accidentally opening an unvalidated IPv6 path. See docs/security-model.md 第十五節.");
        }
    }

    // Rule 20 (partial): duplicate/conflicting protected network definitions.
    private static void ValidateProtectedNetworks(GatewayConfiguration config, ValidationResult result)
    {
        var networks = config.Network.ProtectedNetworks;

        if (networks.Count == 0)
        {
            result.AddWarning("network.protectedNetworks",
                "No protected networks are defined yet. This is acceptable at bootstrap time but no resource can be reached until at least one is configured.");
        }

        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var parsedCidrs = new List<(string Name, uint Network, int Prefix)>();

        foreach (var net in networks)
        {
            if (string.IsNullOrWhiteSpace(net.Name))
            {
                result.AddError("network.protectedNetworks", "A protected network entry has an empty name.");
            }
            else if (!seenNames.Add(net.Name))
            {
                result.AddError("network.protectedNetworks", $"Duplicate protected network name '{net.Name}'.");
            }

            if (!Ipv4NetworkUtils.TryParseCidr(net.Cidr, out var network, out var prefix))
            {
                result.AddError("network.protectedNetworks",
                    $"Protected network '{net.Name}' has an invalid CIDR '{net.Cidr}'.");
                continue;
            }

            foreach (var other in parsedCidrs)
            {
                if (Ipv4NetworkUtils.CidrsOverlap(network, prefix, other.Network, other.Prefix))
                {
                    result.AddError("network.protectedNetworks",
                        $"Protected network '{net.Name}' ({net.Cidr}) overlaps with '{other.Name}'.");
                }
            }

            parsedCidrs.Add((net.Name, network, prefix));
        }
    }
}
