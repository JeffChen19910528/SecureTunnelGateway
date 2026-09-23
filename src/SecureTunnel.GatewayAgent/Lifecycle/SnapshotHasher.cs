using System.Security.Cryptography;
using System.Text;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Lifecycle;

/// <summary>
/// Computes a deterministic SHA-256 content hash over a candidate's Peer/Resource/Policy
/// data, used as the snapshot's integrity identifier. Deliberately excludes any secret
/// material (there is none in these three lists - see docs/security-model.md) and sorts
/// entries by id first so the hash does not depend on Registry file ordering.
/// </summary>
public static class SnapshotHasher
{
    public static string ComputeHash(IReadOnlyList<Peer> peers, IReadOnlyList<ProtectedResource> resources, IReadOnlyList<AccessPolicy> policies)
    {
        var sb = new StringBuilder();

        foreach (var p in peers.OrderBy(x => x.PeerId, StringComparer.Ordinal))
        {
            sb.Append("peer|").Append(p.PeerId).Append('|').Append(p.PublicKey).Append('|')
              .Append(p.AssignedVpnIp).Append('|').Append(p.Status).Append('\n');
        }

        foreach (var r in resources.OrderBy(x => x.ResourceId, StringComparer.Ordinal))
        {
            sb.Append("resource|").Append(r.ResourceId).Append('|').Append(r.Destination).Append('|')
              .Append(r.Protocol).Append('|').Append(r.Port).Append('|').Append(r.PortEnd).Append('|').Append(r.Enabled).Append('\n');
        }

        foreach (var pol in policies.OrderBy(x => x.RuleId, StringComparer.Ordinal))
        {
            sb.Append("policy|").Append(pol.RuleId).Append('|').Append(pol.PeerId).Append('|')
              .Append(pol.ResourceId).Append('|').Append(pol.Enabled).Append('\n');
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
