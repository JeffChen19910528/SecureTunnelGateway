namespace SecureTunnel.GatewayAgent.Routing;

public sealed record ForwardingStatus(bool Ipv4Enabled, bool Ipv6Enabled, string Message);

/// <summary>
/// Read-only inspection of Linux IP forwarding state. Actually enabling forwarding is a
/// root-only, host-mutating action performed by scripts/enable-ip-forwarding.sh (Phase
/// 2.7) after explicit manual confirmation - this service never flips the sysctl itself.
/// </summary>
public interface IForwardingService
{
    Task<ForwardingStatus> CheckStatusAsync(CancellationToken cancellationToken = default);
}
