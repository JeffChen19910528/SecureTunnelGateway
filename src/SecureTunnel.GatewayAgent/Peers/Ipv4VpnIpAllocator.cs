using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Statuses whose peers are considered to still "occupy" their VPN IP, so it cannot be
/// handed out to a different peer. Revoked and Removed peers release their IP (see
/// Models/PeerStatus.cs for the full policy rationale).
/// </summary>
public sealed class Ipv4VpnIpAllocator : IVpnIpAllocator
{
    private static readonly PeerStatus[] OccupyingStatuses = { PeerStatus.Pending, PeerStatus.Active, PeerStatus.Disabled };

    public VpnIpAllocationResult Allocate(GatewayConfiguration config, IReadOnlyCollection<Peer> existingPeers, string? requestedIp = null, string? excludePeerId = null)
    {
        if (!Ipv4NetworkUtils.TryParseIp(config.Network.ClientAddressPoolStart, out var poolStart) ||
            !Ipv4NetworkUtils.TryParseIp(config.Network.ClientAddressPoolEnd, out var poolEnd))
        {
            return Fail("network.clientAddressPoolStart/End is not a valid IP range; cannot allocate. Run `securetunnel-gateway validate` first.");
        }

        if (!string.IsNullOrWhiteSpace(requestedIp))
        {
            if (!Ipv4NetworkUtils.TryParseIp(requestedIp, out var requested))
            {
                return Fail($"'{requestedIp}' is not a valid IPv4 address.");
            }

            if (requested < poolStart || requested > poolEnd)
            {
                return Fail($"'{requestedIp}' is outside the configured client pool ({config.Network.ClientAddressPoolStart}-{config.Network.ClientAddressPoolEnd}).");
            }

            if (!IsAllowedCandidate(config, requested, out var reason))
            {
                return Fail($"'{requestedIp}' cannot be allocated: {reason}");
            }

            if (IsOccupied(existingPeers, requestedIp, excludePeerId))
            {
                return Fail($"'{requestedIp}' is already assigned to another peer.");
            }

            return new VpnIpAllocationResult { Success = true, AllocatedIp = requestedIp, Message = $"Reserved '{requestedIp}'." };
        }

        for (var candidate = poolStart; candidate <= poolEnd; candidate++)
        {
            if (!IsAllowedCandidate(config, candidate, out _))
            {
                continue;
            }

            var candidateStr = ToIpString(candidate);
            if (!IsOccupied(existingPeers, candidateStr, excludePeerId))
            {
                return new VpnIpAllocationResult { Success = true, AllocatedIp = candidateStr, Message = $"Allocated '{candidateStr}'." };
            }
        }

        return Fail($"No free IP available in the client pool ({config.Network.ClientAddressPoolStart}-{config.Network.ClientAddressPoolEnd}). Pool exhausted.");
    }

    public bool IsAvailable(GatewayConfiguration config, IReadOnlyCollection<Peer> existingPeers, string ip, string? excludePeerId = null)
    {
        if (!Ipv4NetworkUtils.TryParseIp(ip, out var address))
        {
            return false;
        }

        return IsAllowedCandidate(config, address, out _) && !IsOccupied(existingPeers, ip, excludePeerId);
    }

    private static bool IsAllowedCandidate(GatewayConfiguration config, uint candidate, out string reason)
    {
        if (Ipv4NetworkUtils.TryParseIp(config.Network.GatewayVpnAddress, out var gatewayIp) && candidate == gatewayIp)
        {
            reason = "conflicts with the Gateway's own VPN address.";
            return false;
        }

        if (Ipv4NetworkUtils.TryParseCidr(config.Network.VpnCidr, out var network, out var prefix))
        {
            var broadcast = prefix == 32 ? network : network | (uint.MaxValue >> prefix);
            if (candidate == network)
            {
                reason = "is the VPN network address.";
                return false;
            }

            if (candidate == broadcast)
            {
                reason = "is the VPN broadcast address.";
                return false;
            }
        }

        reason = string.Empty;
        return true;
    }

    private static bool IsOccupied(IReadOnlyCollection<Peer> existingPeers, string ip, string? excludePeerId) =>
        existingPeers.Any(p =>
            !string.Equals(p.PeerId, excludePeerId, StringComparison.Ordinal) &&
            OccupyingStatuses.Contains(p.Status) &&
            string.Equals(p.AssignedVpnIp, ip, StringComparison.OrdinalIgnoreCase));

    private static string ToIpString(uint value) =>
        $"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}";

    private static VpnIpAllocationResult Fail(string message) => new() { Success = false, Message = message };
}
