using Microsoft.Extensions.Logging.Abstractions;
using SecureTunnel.GatewayAgent.Lifecycle;
using Xunit;

namespace SecureTunnel.GatewayAgent.LifecycleTests;

public sealed class FileOperationLockTests : IDisposable
{
    private readonly List<string> _tempPaths = new();
    private readonly FileOperationLockFactory _factory = new(NullLogger<FileOperationLockFactory>.Instance);

    [Fact]
    public async Task AcquireAsync_NoExistingLock_Succeeds()
    {
        var path = TempPath();

        using var opLock = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(2));

        Assert.True(opLock.Acquired);
        Assert.True(File.Exists(path));
    }

    [Fact]
    public async Task Dispose_ReleasesLock_AllowingReacquisition()
    {
        var path = TempPath();

        var first = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(2));
        Assert.True(first.Acquired);
        first.Dispose();

        using var second = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(2));
        Assert.True(second.Acquired);
    }

    [Fact]
    public async Task AcquireAsync_AlreadyHeldByLiveProcess_TimesOutWithoutStealing()
    {
        var path = TempPath();
        using var holder = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(2));
        Assert.True(holder.Acquired);

        using var second = await _factory.AcquireAsync(path, TimeSpan.FromMilliseconds(500));

        Assert.False(second.Acquired);
        Assert.Contains("another operation appears to be in progress", second.Message);
    }

    [Fact]
    public async Task AcquireAsync_StaleLockFromDeadPid_IsReclaimed()
    {
        var path = TempPath();
        // A PID that (almost certainly) does not correspond to a running process.
        await File.WriteAllTextAsync(path, $"999999|{DateTimeOffset.UtcNow:O}|some-host");

        using var opLock = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(5));

        Assert.True(opLock.Acquired, "a lock file referencing a non-existent PID must be treated as stale and reclaimed");
    }

    [Fact]
    public async Task AcquireAsync_StaleLockByAge_IsReclaimed()
    {
        var path = TempPath();
        // Use our own (very much alive) PID, but an old timestamp - age-based staleness must
        // still win even though the PID check alone would say "still running".
        await File.WriteAllTextAsync(path, $"{Environment.ProcessId}|{DateTimeOffset.UtcNow.AddMinutes(-30):O}|some-host");

        using var opLock = await _factory.AcquireAsync(path, TimeSpan.FromSeconds(5));

        Assert.True(opLock.Acquired, "a lock older than the staleness threshold must be reclaimed regardless of PID liveness");
    }

    [Fact]
    public async Task AcquireAsync_RecentLockFromOwnLiveProcess_IsNotStolen()
    {
        var path = TempPath();
        await File.WriteAllTextAsync(path, $"{Environment.ProcessId}|{DateTimeOffset.UtcNow:O}|some-host");

        using var opLock = await _factory.AcquireAsync(path, TimeSpan.FromMilliseconds(500));

        Assert.False(opLock.Acquired, "a recent lock from a live PID must not be stolen");
    }

    private string TempPath()
    {
        var path = Path.Combine(Path.GetTempPath(), $"securetunnel-lock-{Guid.NewGuid():N}.lock");
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
