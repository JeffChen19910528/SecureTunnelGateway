using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.WireGuard;
using Xunit;

namespace SecureTunnel.GatewayAgent.WireGuardTests;

public sealed class WireGuardServiceTests
{
    [Fact]
    public async Task GetStatusAsync_InterfaceUp_ReturnsUpState()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = _ => MockSystemCommandExecutor.Success("interface: wg-securetunnel\n  public key: abc123\n");
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        var status = await service.GetStatusAsync("wg-securetunnel");

        Assert.Equal(WireGuardInterfaceState.Up, status.State);
        Assert.Contains("wg-securetunnel", mock.Invocations[0].Arguments);
    }

    [Fact]
    public async Task GetStatusAsync_NoSuchDevice_ReturnsNotConfigured()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = _ => MockSystemCommandExecutor.Failure(1, "No such device");
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        var status = await service.GetStatusAsync("wg-securetunnel");

        Assert.Equal(WireGuardInterfaceState.NotConfigured, status.State);
    }

    [Fact]
    public async Task GetStatusAsync_WgNotInstalled_ReturnsUnknownNotCrash()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = _ => MockSystemCommandExecutor.NotFound("command not found");
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        var status = await service.GetStatusAsync("wg-securetunnel");

        Assert.Equal(WireGuardInterfaceState.Unknown, status.State);
        Assert.Contains("BLOCKED", status.Message);
    }

    [Fact]
    public async Task StartAsync_ConstructsCorrectWgQuickCommand()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        await service.StartAsync("wg-securetunnel");

        var invocation = Assert.Single(mock.Invocations);
        Assert.Equal("wg-quick", invocation.Command);
        Assert.Equal(new[] { "up", "wg-securetunnel" }, invocation.Arguments);
    }

    [Fact]
    public async Task StopAsync_ConstructsCorrectWgQuickCommand()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        await service.StopAsync("wg-securetunnel");

        var invocation = Assert.Single(mock.Invocations);
        Assert.Equal("wg-quick", invocation.Command);
        Assert.Equal(new[] { "down", "wg-securetunnel" }, invocation.Arguments);
    }

    [Fact]
    public async Task RestartAsync_CallsDownThenUp_InOrder()
    {
        var mock = new MockSystemCommandExecutor();
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        await service.RestartAsync("wg-securetunnel");

        Assert.Equal(2, mock.Invocations.Count);
        Assert.Equal(new[] { "down", "wg-securetunnel" }, mock.Invocations[0].Arguments);
        Assert.Equal(new[] { "up", "wg-securetunnel" }, mock.Invocations[1].Arguments);
    }

    [Fact]
    public async Task StartAsync_CommandFails_ReturnsFailureNotThrow()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg-quick"] = _ => MockSystemCommandExecutor.Failure(1, "Address already in use");
        var service = new WireGuardService(mock, NullLogger<WireGuardService>.Instance);

        var result = await service.StartAsync("wg-securetunnel");

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
    }

    [Fact]
    public async Task DryRunExecutor_MutatingWgQuickCommand_IsNotExecutedByRealExecutor()
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new WireGuardService(dryRun, NullLogger<WireGuardService>.Instance);

        var result = await service.StartAsync("wg-securetunnel");

        Assert.True(result.Success);
        Assert.Empty(mock.Invocations); // the real executor never saw the mutating command
        Assert.Contains("DRY-RUN", result.StandardOutput);
    }

    [Fact]
    public async Task DryRunExecutor_ReadOnlyWgShow_IsPassedThroughToRealExecutor()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = _ => MockSystemCommandExecutor.Success("interface: wg-securetunnel\n");
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);
        var service = new WireGuardService(dryRun, NullLogger<WireGuardService>.Instance);

        var status = await service.GetStatusAsync("wg-securetunnel");

        Assert.Equal(WireGuardInterfaceState.Up, status.State);
        Assert.Single(mock.Invocations); // read-only query DID reach the real executor
    }
}
