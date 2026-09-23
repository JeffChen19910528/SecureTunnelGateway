namespace SecureTunnel.GatewayAgent.DeploymentTests;

/// <summary>
/// Cheap text-based regression guard for deploy/systemd/securetunnel-gateway.service -
/// catches an accidental revert to the Phase 6 placeholder ExecStart. Real syntax/semantic
/// validation is `systemd-analyze verify`, run manually inside WSL2 Ubuntu 24.04 (see the
/// Phase 6A completion report for that real-environment evidence) - it cannot run as part
/// of this cross-platform test suite since systemd is not available in every CI/dev
/// environment this solution builds in.
/// </summary>
public sealed class SystemdUnitFileTests
{
    [Fact]
    public void ExecStart_PointsAtGatewayServe_NotThePhase6Placeholder()
    {
        var content = ReadUnitFile();

        var execStartLine = content.Split('\n').Single(l => l.TrimStart().StartsWith("ExecStart=", StringComparison.Ordinal));

        Assert.Contains("gateway serve", execStartLine);
        Assert.DoesNotContain("config status", execStartLine);
    }

    [Fact]
    public void NoPlaceholderLanguage_RemainsDescribingExecStart()
    {
        var content = ReadUnitFile();

        Assert.DoesNotContain("Placeholder ExecStart", content);
    }

    [Fact]
    public void ServiceSection_HasConsistentRestartAndLoggingConfiguration()
    {
        var content = ReadUnitFile();

        Assert.Contains("Type=simple", content);
        Assert.Contains("Restart=on-failure", content);
        Assert.Contains("StandardOutput=journal", content);
        Assert.Contains("StandardError=journal", content);
        Assert.Contains("WantedBy=multi-user.target", content);
    }

    private static string ReadUnitFile()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "SecureTunnelGateway.slnx")))
        {
            dir = dir.Parent;
        }

        Assert.NotNull(dir);
        var path = Path.Combine(dir!.FullName, "deploy", "systemd", "securetunnel-gateway.service");
        Assert.True(File.Exists(path), $"Unit file not found at '{path}'.");
        return File.ReadAllText(path);
    }
}
