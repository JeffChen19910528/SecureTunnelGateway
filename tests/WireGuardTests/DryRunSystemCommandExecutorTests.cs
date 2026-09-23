using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.TestSupport;

namespace SecureTunnel.GatewayAgent.WireGuardTests;

/// <summary>
/// Phase 7 hardening: proves dry-run never lets "wg genkey"/"wg pubkey"/"wg set" - the
/// mutating "wg" subcommands - reach the real executor, alongside the existing wg-quick/nft
/// coverage. Defense-in-depth: KeyManagementService already gates real key generation
/// behind its own dry-run check before ever calling the executor, but this test locks in
/// the decorator's own guarantee independent of any particular caller's discipline.
/// </summary>
public sealed class DryRunSystemCommandExecutorTests
{
    [Theory]
    [InlineData("genkey")]
    [InlineData("pubkey")]
    [InlineData("set")]
    public async Task WgMutatingSubcommand_NeverReachesRealExecutor(string subcommand)
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);

        var result = await dryRun.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { subcommand },
            Timeout = TimeSpan.FromSeconds(5)
        });

        Assert.Empty(mock.Invocations);
        Assert.Contains("DRY-RUN", result.StandardOutput);
    }

    [Theory]
    [InlineData("--version")]
    [InlineData("show")]
    public async Task WgReadOnlySubcommand_StillPassesThrough(string subcommand)
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);

        await dryRun.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { subcommand },
            Timeout = TimeSpan.FromSeconds(5)
        });

        Assert.Single(mock.Invocations);
    }

    [Fact]
    public async Task WgGenkey_SensitiveOutput_NeverLoggedEvenAsDryRunPreview()
    {
        var mock = new MockSystemCommandExecutor();
        var dryRun = new DryRunSystemCommandExecutor(mock, NullLogger<DryRunSystemCommandExecutor>.Instance);

        var result = await dryRun.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "genkey" },
            Timeout = TimeSpan.FromSeconds(5),
            SensitiveOutput = true
        });

        Assert.DoesNotContain("genkey", result.StandardOutput, StringComparison.Ordinal);
        Assert.Contains("[arguments redacted]", result.StandardOutput);
    }
}
