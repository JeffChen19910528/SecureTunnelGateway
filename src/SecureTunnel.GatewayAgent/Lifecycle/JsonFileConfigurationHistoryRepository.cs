using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Lifecycle;

/// <summary>
/// Configuration History persisted as a single JSON file - same atomic-write / fail-closed
/// pattern as the Peer/Resource/Policy Registries (see Peers/JsonFilePeerRepository.cs).
/// Never contains any secret: ConfigurationSnapshot deliberately excludes private keys
/// (see Models/ConfigurationSnapshot.cs).
/// </summary>
public sealed class JsonFileConfigurationHistoryRepository : IConfigurationHistoryRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ILogger<JsonFileConfigurationHistoryRepository> _logger;

    public JsonFileConfigurationHistoryRepository(ILogger<JsonFileConfigurationHistoryRepository> logger)
    {
        _logger = logger;
    }

    public async Task<ConfigurationHistory> LoadAsync(string historyPath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(historyPath))
        {
            return new ConfigurationHistory();
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(historyPath, cancellationToken);
        }
        catch (IOException ex)
        {
            throw new ConfigurationHistoryCorruptException($"Could not read configuration history '{historyPath}': {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ConfigurationHistoryCorruptException($"Configuration history '{historyPath}' exists but is empty. Refusing to treat this as fresh history.");
        }

        ConfigurationHistory? history;
        try
        {
            history = JsonSerializer.Deserialize<ConfigurationHistory>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new ConfigurationHistoryCorruptException($"Configuration history '{historyPath}' contains invalid JSON: {ex.Message}");
        }

        if (history is null)
        {
            throw new ConfigurationHistoryCorruptException($"Configuration history '{historyPath}' deserialized to null.");
        }

        var duplicateVersions = history.Versions.GroupBy(v => v.Version).FirstOrDefault(g => g.Count() > 1);
        if (duplicateVersions is not null)
        {
            throw new ConfigurationHistoryCorruptException($"Configuration history '{historyPath}' contains duplicate version number {duplicateVersions.Key}.");
        }

        return history;
    }

    public async Task SaveAsync(string historyPath, ConfigurationHistory history, CancellationToken cancellationToken = default)
    {
        var duplicateVersions = history.Versions.GroupBy(v => v.Version).FirstOrDefault(g => g.Count() > 1);
        if (duplicateVersions is not null)
        {
            throw new ConfigurationHistoryCorruptException($"Refusing to save configuration history with duplicate version number {duplicateVersions.Key}.");
        }

        var directory = Path.GetDirectoryName(historyPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = historyPath + $".tmp-{Guid.NewGuid():N}";
        var json = JsonSerializer.Serialize(history, SerializerOptions);
        await File.WriteAllTextAsync(tempPath, json, cancellationToken);

        try
        {
            File.Move(tempPath, historyPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(tempPath))
            {
                try { File.Delete(tempPath); } catch { /* best-effort */ }
            }
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(historyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        _logger.LogInformation("Saved configuration history ({Count} version(s), active={Active}, lastKnownGood={Lkg}) to {Path}",
            history.Versions.Count, history.ActiveVersion, history.LastKnownGoodVersion, historyPath);
    }
}
