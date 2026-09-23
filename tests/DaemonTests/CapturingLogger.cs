using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Daemon;

namespace SecureTunnel.GatewayAgent.DaemonTests;

/// <summary>Captures every formatted log message so tests can assert on daemon output (e.g. no secret leakage) without parsing console/journald output.</summary>
public sealed class CapturingLogger : ILogger<GatewayDaemonService>
{
    public ConcurrentQueue<string> Messages { get; } = new();

    public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        Messages.Enqueue(formatter(state, exception));
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();
        public void Dispose() { }
    }
}
