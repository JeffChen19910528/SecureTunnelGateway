using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class FirewallServiceTests
{
    [Fact]
    public async Task ValidateSyntaxAsync_ConstructsCorrectNftCommand()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        await service.ValidateSyntaxAsync("/tmp/ruleset.conf");

        var invocation = Assert.Single(mock.Invocations);
        Assert.Equal("nft", invocation.Command);
        Assert.Equal(new[] { "-c", "-f", "/tmp/ruleset.conf" }, invocation.Arguments);
    }

    [Fact]
    public async Task ApplyAsync_ConstructsCorrectNftCommand()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        await service.ApplyAsync("/tmp/ruleset.conf");

        var invocation = Assert.Single(mock.Invocations);
        Assert.Equal(new[] { "-f", "/tmp/ruleset.conf" }, invocation.Arguments);
    }

    [Fact]
    public async Task RemoveTableAsync_OnlyTargetsSecuretunnelTable()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        await service.RemoveTableAsync();

        var invocation = Assert.Single(mock.Invocations);
        Assert.Equal(new[] { "delete", "table", "inet", "securetunnel" }, invocation.Arguments);
    }

    [Fact]
    public async Task GetStatusAsync_TablePresent_ReturnsPresent()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.Success("table inet securetunnel {\n...\n}\n");
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        var status = await service.GetStatusAsync();

        Assert.Equal(FirewallTableState.Present, status.State);
    }

    [Fact]
    public async Task GetStatusAsync_TableMissing_ReturnsNotPresentNotError()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.Failure(1, "Error: No such file or directory");
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        var status = await service.GetStatusAsync();

        Assert.Equal(FirewallTableState.NotPresent, status.State);
    }

    [Fact]
    public async Task GetStatusAsync_NftNotInstalled_ReturnsUnknownNotCrash()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("command not found");
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        var status = await service.GetStatusAsync();

        Assert.Equal(FirewallTableState.Unknown, status.State);
        Assert.Contains("BLOCKED", status.Message);
    }

    [Fact]
    public async Task ApplyAsync_DryRunExecutor_NeverReachesRealExecutor()
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new FirewallService(dryRun, NullLogger<FirewallService>.Instance);

        var result = await service.ApplyAsync("/tmp/ruleset.conf");

        Assert.True(result.Success);
        Assert.Empty(mock.Invocations);
        Assert.Contains("DRY-RUN", result.StandardOutput);
    }

    [Fact]
    public async Task ValidateSyntaxAsync_DryRunExecutor_IsPassedThroughAsReadOnly()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.Success("");
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new FirewallService(dryRun, NullLogger<FirewallService>.Instance);

        var result = await service.ValidateSyntaxAsync("/tmp/ruleset.conf");

        Assert.True(result.Success);
        Assert.Single(mock.Invocations); // syntax check (-c -f) is read-only, reaches the real executor
    }

    [Fact]
    public async Task ShowAsync_DryRunExecutor_IsPassedThroughAsReadOnly()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.Success("table inet securetunnel {}");
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new FirewallService(dryRun, NullLogger<FirewallService>.Instance);

        var output = await service.ShowAsync();

        Assert.Contains("securetunnel", output);
        Assert.Single(mock.Invocations);
    }

    [Fact]
    public async Task RemoveTableAsync_DryRunExecutor_IsInterceptedAsMutating()
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new FirewallService(dryRun, NullLogger<FirewallService>.Instance);

        var result = await service.RemoveTableAsync();

        Assert.True(result.Success);
        Assert.Empty(mock.Invocations); // "delete" is mutating, never reaches the real executor
    }

    [Fact]
    public async Task CheckInstalledAsync_NftNotFound_ReturnsFalseNotThrow()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["nft"] = _ => MockSystemCommandExecutor.NotFound("not found");
        var service = new FirewallService(mock, NullLogger<FirewallService>.Instance);

        var installed = await service.CheckInstalledAsync();

        Assert.False(installed);
    }
}
