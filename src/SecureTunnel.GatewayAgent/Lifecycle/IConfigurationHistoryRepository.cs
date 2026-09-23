using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Lifecycle;

public sealed class ConfigurationHistoryCorruptException : Exception
{
    public ConfigurationHistoryCorruptException(string message) : base(message) { }
}

public interface IConfigurationHistoryRepository
{
    /// <summary>Returns a fresh, empty history if the file does not exist yet - not an error.</summary>
    Task<ConfigurationHistory> LoadAsync(string historyPath, CancellationToken cancellationToken = default);

    Task SaveAsync(string historyPath, ConfigurationHistory history, CancellationToken cancellationToken = default);
}
