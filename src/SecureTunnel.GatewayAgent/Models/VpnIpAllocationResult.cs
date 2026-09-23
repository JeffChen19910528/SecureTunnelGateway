namespace SecureTunnel.GatewayAgent.Models;

public sealed class VpnIpAllocationResult
{
    public required bool Success { get; init; }
    public string? AllocatedIp { get; init; }
    public required string Message { get; init; }
}
