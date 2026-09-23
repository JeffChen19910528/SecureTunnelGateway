using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.TestSupport;
using Xunit;

namespace SecureTunnel.GatewayAgent.WireGuardTests;

public sealed class KeyManagementServiceTests : IDisposable
{
    private readonly List<string> _tempPaths = new();

    [Fact]
    public void SensitiveString_ToString_NeverExposesRealValue()
    {
        var secret = new SensitiveString("SUPER_SECRET_PRIVATE_KEY_VALUE=");

        var stringified = secret.ToString();
        var interpolated = $"{secret}";

        Assert.DoesNotContain("SUPER_SECRET_PRIVATE_KEY_VALUE", stringified);
        Assert.DoesNotContain("SUPER_SECRET_PRIVATE_KEY_VALUE", interpolated);
        Assert.Equal("SUPER_SECRET_PRIVATE_KEY_VALUE=", secret.Reveal());
    }

    [Fact]
    public async Task GenerateServerKeyPairAsync_WgNotInstalled_ReturnsBlockedNotThrow()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = _ => MockSystemCommandExecutor.NotFound("wg: command not found");
        var service = new KeyManagementService(mock, NullLogger<KeyManagementService>.Instance);

        var result = await service.GenerateServerKeyPairAsync(TempPath(), TempPath(), new KeyGenerationOptions());

        Assert.False(result.Success);
        Assert.Contains("BLOCKED", result.Message);
    }

    [Fact]
    public async Task GenerateServerKeyPairAsync_ExistingKeyWithoutForce_RefusesToOverwrite()
    {
        var privateKeyPath = TempPath();
        await File.WriteAllTextAsync(privateKeyPath, "EXISTING_KEY_CONTENT=");
        var mock = new MockSystemCommandExecutor(); // should never be called
        var service = new KeyManagementService(mock, NullLogger<KeyManagementService>.Instance);

        var result = await service.GenerateServerKeyPairAsync(privateKeyPath, TempPath(), new KeyGenerationOptions { Force = false });

        Assert.False(result.Success);
        Assert.Contains("already exists", result.Message);
        Assert.Empty(mock.Invocations);
        Assert.Equal("EXISTING_KEY_CONTENT=", await File.ReadAllTextAsync(privateKeyPath));
    }

    [Fact]
    public async Task GenerateServerKeyPairAsync_DryRun_DoesNotCallGenkeyOrWriteFiles()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = req => req.Arguments.Contains("--version")
            ? MockSystemCommandExecutor.Success("wg 1.0.0")
            : MockSystemCommandExecutor.Success("SHOULD_NOT_BE_CALLED_IN_DRY_RUN=");
        var service = new KeyManagementService(mock, NullLogger<KeyManagementService>.Instance);
        var privateKeyPath = TempPath();
        var publicKeyPath = TempPath();

        var result = await service.GenerateServerKeyPairAsync(privateKeyPath, publicKeyPath, new KeyGenerationOptions { DryRun = true });

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.False(File.Exists(privateKeyPath));
        Assert.False(File.Exists(publicKeyPath));
        Assert.DoesNotContain(mock.Invocations, i => i.Arguments.Contains("genkey"));
    }

    [Fact]
    public async Task GenerateServerKeyPairAsync_Success_WritesPrivateKeyAndPublicKeyNeverLogsPrivateKey()
    {
        var mock = new MockSystemCommandExecutor();
        mock.Handlers["wg"] = req =>
        {
            if (req.Arguments.Contains("--version")) return MockSystemCommandExecutor.Success("wg 1.0.0");
            if (req.Arguments.Contains("genkey")) return MockSystemCommandExecutor.Success("PRIVATE_KEY_VALUE=\n");
            if (req.Arguments.Contains("pubkey")) return MockSystemCommandExecutor.Success("PUBLIC_KEY_VALUE=\n");
            throw new InvalidOperationException("unexpected wg invocation");
        };
        var service = new KeyManagementService(mock, NullLogger<KeyManagementService>.Instance);
        var privateKeyPath = TempPath();
        var publicKeyPath = TempPath();

        var result = await service.GenerateServerKeyPairAsync(privateKeyPath, publicKeyPath, new KeyGenerationOptions());

        Assert.True(result.Success);
        Assert.Equal("PUBLIC_KEY_VALUE=", result.PublicKey);
        Assert.Equal("PRIVATE_KEY_VALUE=", (await File.ReadAllTextAsync(privateKeyPath)).Trim());
        Assert.Equal("PUBLIC_KEY_VALUE=", (await File.ReadAllTextAsync(publicKeyPath)).Trim());

        // The result object surfaced to CLI/logging must never carry the private key.
        Assert.DoesNotContain("PRIVATE_KEY_VALUE", result.Message);

        // The `wg pubkey` call must receive the private key via stdin, never as a
        // command-line argument (which would be visible via `ps`).
        var pubkeyInvocation = mock.Invocations.Single(i => i.Arguments.Contains("pubkey"));
        Assert.DoesNotContain(pubkeyInvocation.Arguments, a => a.Contains("PRIVATE_KEY_VALUE"));
        Assert.Equal("PRIVATE_KEY_VALUE=", pubkeyInvocation.StandardInput);
        Assert.True(pubkeyInvocation.SensitiveOutput);

        var genkeyInvocation = mock.Invocations.Single(i => i.Arguments.Contains("genkey"));
        Assert.True(genkeyInvocation.SensitiveOutput);
    }

    [Fact]
    public void CheckPrivateKeyPermissions_FileDoesNotExist_ReturnsNotExists()
    {
        var service = new KeyManagementService(new MockSystemCommandExecutor(), NullLogger<KeyManagementService>.Instance);

        var result = service.CheckPrivateKeyPermissions("/definitely/does/not/exist.key");

        Assert.False(result.Exists);
        Assert.False(result.PermissionsOk);
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-keytest-{Guid.NewGuid():N}.key");
        _tempPaths.Add(path);
        return path;
    }

    public void Dispose()
    {
        foreach (var p in _tempPaths)
        {
            try { if (File.Exists(p)) File.Delete(p); } catch { /* best-effort */ }
        }
    }
}
