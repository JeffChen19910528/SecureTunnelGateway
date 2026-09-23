using System.Net;

namespace SecureTunnel.GatewayAgent.Validation;

/// <summary>
/// Minimal IPv4 CIDR helpers used by configuration validation. Deliberately IPv4-only:
/// IPv6 is not part of the validated data plane yet (see docs/security-model.md 第十五節).
/// </summary>
public static class Ipv4NetworkUtils
{
    public static bool TryParseIp(string value, out uint address)
    {
        address = 0;
        if (!IPAddress.TryParse(value, out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        address = ToUInt32(ip);
        return true;
    }

    public static bool TryParseCidr(string cidr, out uint networkAddress, out int prefixLength)
    {
        networkAddress = 0;
        prefixLength = 0;

        var parts = cidr.Split('/');
        if (parts.Length != 2)
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[0], out var ip) || ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            return false;
        }

        if (!int.TryParse(parts[1], out prefixLength) || prefixLength < 0 || prefixLength > 32)
        {
            return false;
        }

        networkAddress = ToUInt32(ip);
        return true;
    }

    public static bool IsAddressInCidr(uint address, uint networkAddress, int prefixLength)
    {
        if (prefixLength == 0)
        {
            return true;
        }

        var mask = prefixLength == 32 ? 0xFFFFFFFFu : ~(0xFFFFFFFFu >> prefixLength);
        return (address & mask) == (networkAddress & mask);
    }

    public static bool CidrsOverlap(uint networkA, int prefixA, uint networkB, int prefixB)
    {
        var minPrefix = Math.Min(prefixA, prefixB);
        var mask = minPrefix == 0 ? 0u : (minPrefix == 32 ? 0xFFFFFFFFu : ~(0xFFFFFFFFu >> minPrefix));
        return (networkA & mask) == (networkB & mask);
    }

    private static uint ToUInt32(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        return ((uint)bytes[0] << 24) | ((uint)bytes[1] << 16) | ((uint)bytes[2] << 8) | bytes[3];
    }
}
