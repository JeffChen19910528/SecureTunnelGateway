using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Lifecycle;

/// <summary>
/// A held, single-writer operation lock. Disposing releases it. Never dispose without
/// having checked <see cref="Acquired"/> was true for the result you got back from
/// <see cref="IOperationLockFactory.AcquireAsync"/> - see FileOperationLock for the
/// concrete (cross-platform) implementation.
/// </summary>
public interface IOperationLock : IDisposable
{
    bool Acquired { get; }

    /// <summary>Set when Acquired is false: explains who holds the lock or why acquisition failed.</summary>
    string? Message { get; }
}

public interface IOperationLockFactory
{
    /// <summary>
    /// Attempts to acquire the single-writer lock at <paramref name="lockPath"/>, retrying
    /// until <paramref name="timeout"/> elapses. Returns a lock with Acquired = false (never
    /// throws for the "someone else holds it" case) if the timeout is reached - callers must
    /// check <see cref="IOperationLock.Acquired"/> before proceeding.
    /// </summary>
    Task<IOperationLock> AcquireAsync(string lockPath, TimeSpan timeout, CancellationToken cancellationToken = default);
}
