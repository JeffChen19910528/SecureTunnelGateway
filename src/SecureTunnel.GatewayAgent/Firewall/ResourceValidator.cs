using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Validates a single ProtectedResource's fields. Deliberately IPv4-only (see
/// docs/firewall-model.md 第二節) and deliberately rejects hostname destinations -
/// resolving a hostname at firewall-evaluation time would make the effective ruleset
/// depend on DNS, which is exactly the kind of "silent, time-varying authorization"
/// docs/security-model.md warns against.
/// </summary>
public static class ResourceValidator
{
    public static void Validate(ProtectedResource resource, ValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(resource.Name) || resource.Name.Length > 100 || resource.Name.Any(char.IsControl))
        {
            result.AddError("name", "Resource name must be non-empty, at most 100 characters, and contain no control characters.");
        }

        ValidateDestination(resource.Destination, result);
        ValidatePort(resource.Port, "port", result);

        if (resource.PortEnd is { } end)
        {
            ValidatePort(end, "portEnd", result);
            if (end < resource.Port)
            {
                result.AddError("portEnd", $"portEnd ({end}) must be >= port ({resource.Port}).");
            }
        }
    }

    private static void ValidateDestination(string destination, ValidationResult result)
    {
        if (string.IsNullOrWhiteSpace(destination))
        {
            result.AddError("destination", "Destination must not be empty.",
                "Provide an explicit IPv4 address or CIDR, e.g. \"10.20.0.10\" or \"10.20.0.0/28\". Hostnames are not supported.");
            return;
        }

        var trimmed = destination.Trim();

        if (trimmed.Contains(':'))
        {
            result.AddError("destination", $"'{trimmed}' looks like an IPv6 address. IPv6 resources are not supported in this release.");
            return;
        }

        bool isValid;
        uint network = 0;
        int prefix = 32;

        if (trimmed.Contains('/'))
        {
            isValid = Ipv4NetworkUtils.TryParseCidr(trimmed, out network, out prefix);
            if (!isValid)
            {
                result.AddError("destination", $"'{trimmed}' is not a valid IPv4 CIDR.");
                return;
            }
        }
        else
        {
            isValid = Ipv4NetworkUtils.TryParseIp(trimmed, out network);
            if (!isValid)
            {
                result.AddError("destination", $"'{trimmed}' is not a valid IPv4 address or hostname is not supported - use an explicit IPv4 address or CIDR.");
                return;
            }
        }

        if (prefix <= 8)
        {
            result.AddError("destination",
                $"'{trimmed}' is far too broad for a single resource (prefix /{prefix}). " +
                "This looks like an attempt at unrestricted/LAN-wide access, which SecureTunnel Gateway refuses to generate.",
                "Define one resource per specific host or a narrow subnet (e.g. /28 or smaller), never a broad network.");
        }
    }

    private static void ValidatePort(int port, string field, ValidationResult result)
    {
        if (port < 1 || port > 65535)
        {
            result.AddError(field, $"Port {port} is out of range (must be 1-65535).");
        }
    }
}
