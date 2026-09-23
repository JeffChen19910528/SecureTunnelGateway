using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.TestSupport;

/// <summary>Test double for <see cref="IEnvironmentChecker"/> returning a canned result set.</summary>
public sealed class FakeEnvironmentChecker : IEnvironmentChecker
{
    private readonly IReadOnlyList<EnvironmentCheckResult> _results;

    public FakeEnvironmentChecker(IReadOnlyList<EnvironmentCheckResult> results)
    {
        _results = results;
    }

    public Task<IReadOnlyList<EnvironmentCheckResult>> RunChecksAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_results);

    public static FakeEnvironmentChecker AllHealthy() => new(new[]
    {
        new EnvironmentCheckResult("os.detected", CheckStatus.Pass, "Ubuntu 24.04"),
        new EnvironmentCheckResult("kernel.version", CheckStatus.Pass, "6.8.0"),
        new EnvironmentCheckResult("wireguard.wg", CheckStatus.Pass, "wg found"),
        new EnvironmentCheckResult("wireguard.wg-quick", CheckStatus.Pass, "wg-quick found"),
        new EnvironmentCheckResult("wireguard.kernel-module", CheckStatus.Pass, "module present"),
        new EnvironmentCheckResult("nftables.nft", CheckStatus.Pass, "nft found"),
        new EnvironmentCheckResult("networking.ipv4-forward", CheckStatus.Pass, "enabled"),
        new EnvironmentCheckResult("networking.interfaces", CheckStatus.Pass, "eth0"),
        new EnvironmentCheckResult("directories.config", CheckStatus.Pass, "exists"),
        new EnvironmentCheckResult("directories.log", CheckStatus.Pass, "exists"),
        new EnvironmentCheckResult("privileges.root", CheckStatus.Pass, "root"),
        new EnvironmentCheckResult("systemd.running", CheckStatus.Pass, "systemd")
    });

    public static FakeEnvironmentChecker MissingWireGuard()
    {
        var items = AllHealthy()._results.ToList();
        items.RemoveAll(r => r.Id is "wireguard.wg" or "wireguard.wg-quick");
        items.Add(new EnvironmentCheckResult("wireguard.wg", CheckStatus.Blocked, "'wg' command not found."));
        items.Add(new EnvironmentCheckResult("wireguard.wg-quick", CheckStatus.Blocked, "'wg-quick' command not found."));
        return new FakeEnvironmentChecker(items);
    }

    public static FakeEnvironmentChecker MissingNftables()
    {
        var items = AllHealthy()._results.ToList();
        items.RemoveAll(r => r.Id == "nftables.nft");
        items.Add(new EnvironmentCheckResult("nftables.nft", CheckStatus.Blocked, "'nft' command not found."));
        return new FakeEnvironmentChecker(items);
    }

    public static FakeEnvironmentChecker MissingPermissions()
    {
        var items = AllHealthy()._results.ToList();
        items.RemoveAll(r => r.Id == "privileges.root");
        items.Add(new EnvironmentCheckResult("privileges.root", CheckStatus.Warn, "Not running as root."));
        return new FakeEnvironmentChecker(items);
    }
}
