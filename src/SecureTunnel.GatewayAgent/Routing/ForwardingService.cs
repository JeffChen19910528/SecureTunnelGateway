using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.Routing;

public sealed class ForwardingService : IForwardingService
{
    private readonly ISystemCommandExecutor _executor;

    public ForwardingService(ISystemCommandExecutor executor)
    {
        _executor = executor;
    }

    public async Task<ForwardingStatus> CheckStatusAsync(CancellationToken cancellationToken = default)
    {
        var ipv4 = await ReadSysctlBool("net.ipv4.ip_forward", cancellationToken);
        var ipv6 = await ReadSysctlBool("net.ipv6.conf.all.forwarding", cancellationToken);

        var message = ipv4 is null
            ? "Could not determine IPv4 forwarding status ('sysctl' unavailable or unreadable)."
            : $"IPv4 forwarding: {(ipv4.Value ? "enabled" : "disabled")}; IPv6 forwarding: " +
              (ipv6 is null ? "unknown" : ipv6.Value ? "enabled" : "disabled");

        return new ForwardingStatus(ipv4 ?? false, ipv6 ?? false, message);
    }

    private async Task<bool?> ReadSysctlBool(string key, CancellationToken cancellationToken)
    {
        var result = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "sysctl",
            Arguments = new[] { "-n", key },
            Timeout = TimeSpan.FromSeconds(5)
        }, cancellationToken);

        if (!result.Success)
        {
            return null;
        }

        var value = result.StandardOutput.Trim();
        return value switch
        {
            "1" => true,
            "0" => false,
            _ => null
        };
    }
}
