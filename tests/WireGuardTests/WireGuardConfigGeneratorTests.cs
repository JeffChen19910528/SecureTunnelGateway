using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.TestSupport;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace SecureTunnel.GatewayAgent.WireGuardTests;

public sealed class WireGuardConfigGeneratorTests : IDisposable
{
    private readonly List<string> _tempPaths = new();
    private readonly WireGuardConfigGenerator _generator;

    public WireGuardConfigGeneratorTests()
    {
        _generator = new WireGuardConfigGenerator(new GatewayConfigurationValidator(), NullLogger<WireGuardConfigGenerator>.Instance);
    }

    [Fact]
    public async Task GenerateAsync_DryRun_DoesNotWriteAnyFile()
    {
        var config = TestConfigurationFactory.CreateValid();
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { DryRun = true, OutputPath = outputPath });

        Assert.True(result.Success);
        Assert.True(result.DryRun);
        Assert.Null(result.WrittenPath);
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_DryRun_NeverIncludesRealPrivateKeyContent()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = WritePrivateKeyFile("THIS_IS_A_FAKE_TEST_PRIVATE_KEY_VALUE=");

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { DryRun = true });

        Assert.DoesNotContain("THIS_IS_A_FAKE_TEST_PRIVATE_KEY_VALUE", result.RenderedForReview);
        Assert.Contains("<loaded from", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_InvalidConfiguration_FailsAndReturnsIssuesWithoutWriting()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.Security.FailClosed = false; // makes the configuration invalid
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { OutputPath = outputPath });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Field == "security.failClosed");
        Assert.False(File.Exists(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_ValidConfigurationWithKeyPresent_WritesFileWithRealKey()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = WritePrivateKeyFile("REAL_TEST_KEY_CONTENT=");
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { OutputPath = outputPath });

        Assert.True(result.Success);
        Assert.Equal(outputPath, result.WrittenPath);
        Assert.True(File.Exists(outputPath));

        var writtenContent = await File.ReadAllTextAsync(outputPath);
        Assert.Contains("REAL_TEST_KEY_CONTENT=", writtenContent);

        // The value returned to the caller (which callers may log/print) must never
        // contain the real key, even though the file on disk does.
        Assert.DoesNotContain("REAL_TEST_KEY_CONTENT=", result.RenderedForReview);
    }

    [Fact]
    public async Task GenerateAsync_ExistingFileWithoutForce_FailsWithoutOverwriting()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = WritePrivateKeyFile("KEY=");
        var outputPath = TempPath();
        await File.WriteAllTextAsync(outputPath, "PRE-EXISTING CONTENT");

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { OutputPath = outputPath, Force = false });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Field == "output.path");
        Assert.Equal("PRE-EXISTING CONTENT", await File.ReadAllTextAsync(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_ExistingFileWithForce_Overwrites()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = WritePrivateKeyFile("KEY=");
        var outputPath = TempPath();
        await File.WriteAllTextAsync(outputPath, "PRE-EXISTING CONTENT");

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { OutputPath = outputPath, Force = true });

        Assert.True(result.Success);
        Assert.Contains("[Interface]", await File.ReadAllTextAsync(outputPath));
    }

    [Fact]
    public async Task GenerateAsync_MissingPrivateKeyFile_FailsGracefullyWithoutThrowing()
    {
        var config = TestConfigurationFactory.CreateValid();
        config.WireGuard.PrivateKeyPath = "/definitely/does/not/exist/server.key";
        var outputPath = TempPath();

        var result = await _generator.GenerateAsync(config, Array.Empty<Peer>(), new ConfigGenerationOptions { OutputPath = outputPath });

        Assert.False(result.Success);
        Assert.Contains(result.ValidationIssues, i => i.Message.Contains("private key not found", StringComparison.OrdinalIgnoreCase));
    }

    private string WritePrivateKeyFile(string content)
    {
        var path = TempPath();
        File.WriteAllText(path, content);
        return path;
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-wgtest-{Guid.NewGuid():N}");
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
