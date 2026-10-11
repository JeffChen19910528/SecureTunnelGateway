using Microsoft.Extensions.Logging;

namespace SecureTunnel.GatewayAgent.Lifecycle;

/// <summary>
/// Single-writer lock implemented as an exclusively-created lock file. Works identically
/// on Linux and Windows dev machines because it relies only on <see cref="FileMode.CreateNew"/>
/// (atomically fails if the file already exists) plus <see cref="FileShare.None"/> (no other
/// process can even read the file while we hold the handle) - both are standard .NET file
/// I/O guarantees on either OS, not a Linux-specific flock/fcntl mechanism. This does NOT
/// coordinate across machines/nodes - see docs/security-model.md "Concurrency" for the
/// explicit single-Gateway scope of this guarantee.
///
/// Stale lock handling: the lock file's content is "{pid}|{timestampUtc}|{machineName}".
/// If acquisition fails because the file exists, we check whether the owning PID is still
/// a running process (Linux/Windows both support Process.GetProcessById) OR whether the
/// lock is older than <see cref="StaleAfter"/>; if either is true we treat it as abandoned
/// (e.g. the Gateway Agent crashed mid-operation), delete it, and retry once.
/// </summary>
public sealed class FileOperationLockFactory : IOperationLockFactory
{
    private static readonly TimeSpan StaleAfter = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RetryInterval = TimeSpan.FromMilliseconds(200);

    private readonly ILogger<FileOperationLockFactory> _logger;

    public FileOperationLockFactory(ILogger<FileOperationLockFactory> logger)
    {
        _logger = logger;
    }

    public async Task<IOperationLock> AcquireAsync(string lockPath, TimeSpan timeout, CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(lockPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var deadline = DateTimeOffset.UtcNow + timeout;
        var triedStaleCleanup = false;

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                var stream = new FileStream(lockPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);
                var content = $"{Environment.ProcessId}|{DateTimeOffset.UtcNow:O}|{Environment.MachineName}";
                var bytes = System.Text.Encoding.UTF8.GetBytes(content);
                await stream.WriteAsync(bytes, cancellationToken);
                await stream.FlushAsync(cancellationToken);
                _logger.LogInformation("Acquired operation lock {LockPath} (pid {Pid})", lockPath, Environment.ProcessId);
                return new FileOperationLock(lockPath, stream, acquired: true);
            }
            catch (IOException)
            {
                // File already exists (or is held) - fall through to staleness/timeout handling.
            }

            if (!triedStaleCleanup && IsStale(lockPath))
            {
                triedStaleCleanup = true;
                _logger.LogWarning("Operation lock {LockPath} appears stale; removing and retrying once.", lockPath);
                TryDeleteStaleLock(lockPath);
                continue; // retry immediately, don't count this attempt against the timeout
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                var holder = TryReadLockInfo(lockPath) ?? "unknown";
                return new FileOperationLock(lockPath, stream: null, acquired: false)
                {
                    Message = $"Could not acquire operation lock '{lockPath}' within {timeout.TotalSeconds:0}s; " +
                              $"another operation appears to be in progress (held by: {holder}). " +
                              "If you are certain no other securetunnel-gateway process is running, the lock may be stale; " +
                              "it will be automatically reclaimed after it is older than 10 minutes."
                };
            }

            await Task.Delay(RetryInterval, cancellationToken);
        }
    }

    private bool IsStale(string lockPath)
    {
        if (!File.Exists(lockPath))
        {
            return false;
        }

        try
        {
            var content = File.ReadAllText(lockPath);
            var parts = content.Split('|');
            if (parts.Length < 2)
            {
                return true; // unreadable/corrupt lock content - treat as stale
            }

            if (int.TryParse(parts[0], out var pid))
            {
                if (!IsProcessRunning(pid))
                {
                    return true;
                }
            }

            if (DateTimeOffset.TryParse(parts[1], out var lockedAt) && DateTimeOffset.UtcNow - lockedAt > StaleAfter)
            {
                return true;
            }

            return false;
        }
        catch (IOException)
        {
            // The holder keeps the file open with FileShare.None, so reading it fails while the lock is
            // genuinely held (on Linux via flock). That is NOT evidence of staleness - deleting it would
            // steal a live lock. Fall back to the file's age, which the 10-minute rule still bounds.
            return DateTimeOffset.UtcNow - File.GetLastWriteTimeUtc(lockPath) > StaleAfter;
        }
        catch
        {
            return true; // couldn't even read it - treat as stale rather than blocking forever
        }
    }

    private static bool IsProcessRunning(int pid)
    {
        try
        {
            using var process = System.Diagnostics.Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false; // no such process
        }
        catch
        {
            return true; // couldn't determine - assume running, safer to not steal the lock
        }
    }

    private void TryDeleteStaleLock(string lockPath)
    {
        try
        {
            File.Delete(lockPath);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to remove stale lock {LockPath}", lockPath);
        }
    }

    private static string? TryReadLockInfo(string lockPath)
    {
        try
        {
            return File.Exists(lockPath) ? File.ReadAllText(lockPath) : null;
        }
        catch
        {
            return null;
        }
    }
}

public sealed class FileOperationLock : IOperationLock
{
    private readonly string _lockPath;
    private readonly FileStream? _stream;

    public bool Acquired { get; }
    public string? Message { get; init; }

    internal FileOperationLock(string lockPath, FileStream? stream, bool acquired)
    {
        _lockPath = lockPath;
        _stream = stream;
        Acquired = acquired;
    }

    public void Dispose()
    {
        if (!Acquired)
        {
            return;
        }

        _stream?.Dispose();

        try
        {
            File.Delete(_lockPath);
        }
        catch
        {
            // Best-effort: a failure to delete the lock file on release will make it look
            // stale to the next acquirer, which is handled by staleness detection above.
        }
    }
}
