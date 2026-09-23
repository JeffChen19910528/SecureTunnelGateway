namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// A single internal service that authorized Peers may be granted access to (a website,
/// an API, a TCP service such as a database, ...). Destination is always an explicit
/// IPv4 address or CIDR - Phase 4 deliberately does not support hostname-based resources
/// (see docs/firewall-model.md 第二節). Serialized to the JSON resource registry
/// (Firewall/JsonFileResourceRepository.cs); this model has no fields that would ever be
/// sensitive, so nothing here needs redaction.
/// </summary>
public sealed class ProtectedResource
{
    public required string ResourceId { get; init; }
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>IPv4 address or CIDR, e.g. "10.20.0.10" or "10.20.0.0/28". Never a hostname.</summary>
    public required string Destination { get; set; }

    public required Protocol Protocol { get; set; }

    /// <summary>Single port, or the start of a range when <see cref="PortEnd"/> is set.</summary>
    public required int Port { get; set; }

    /// <summary>Null for a single port; otherwise the inclusive end of the port range (must be &gt;= Port).</summary>
    public int? PortEnd { get; set; }

    public bool Enabled { get; set; } = true;

    public required DateTimeOffset CreatedAtUtc { get; init; }
    public DateTimeOffset UpdatedAtUtc { get; set; }
}
