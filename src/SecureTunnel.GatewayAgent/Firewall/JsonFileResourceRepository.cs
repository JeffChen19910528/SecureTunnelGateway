using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>
/// Protected Resource registry, persisted the same way as the Phase 3 Peer registry
/// (Peers/JsonFilePeerRepository.cs) - single JSON array, atomic temp-file-then-rename
/// write, fail-closed read validation. See docs/configuration-guide.md for why JSON was
/// chosen over a database for this MVP; the same reasoning applies here.
/// </summary>
public sealed class JsonFileResourceRepository : IResourceRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ILogger<JsonFileResourceRepository> _logger;

    public JsonFileResourceRepository(ILogger<JsonFileResourceRepository> logger)
    {
        _logger = logger;
    }

    public async Task<IReadOnlyList<ProtectedResource>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(storePath))
        {
            return Array.Empty<ProtectedResource>();
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(storePath, cancellationToken);
        }
        catch (IOException ex)
        {
            throw new ResourceRegistryCorruptException($"Could not read resource registry '{storePath}': {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            throw new ResourceRegistryCorruptException($"Resource registry '{storePath}' exists but is empty. Refusing to treat this as an empty registry.");
        }

        List<ProtectedResource>? resources;
        try
        {
            resources = JsonSerializer.Deserialize<List<ProtectedResource>>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new ResourceRegistryCorruptException($"Resource registry '{storePath}' contains invalid JSON: {ex.Message}");
        }

        if (resources is null)
        {
            throw new ResourceRegistryCorruptException($"Resource registry '{storePath}' deserialized to null.");
        }

        ValidateNoDuplicates(resources, storePath);
        return resources;
    }

    public async Task SaveAllAsync(string storePath, IReadOnlyList<ProtectedResource> resources, CancellationToken cancellationToken = default)
    {
        ValidateNoDuplicates(resources, storePath);

        var directory = Path.GetDirectoryName(storePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = storePath + $".tmp-{Guid.NewGuid():N}";
        var json = JsonSerializer.Serialize(resources, SerializerOptions);
        await File.WriteAllTextAsync(tempPath, json, cancellationToken);

        try
        {
            File.Move(tempPath, storePath, overwrite: true);
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
            File.SetUnixFileMode(storePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        _logger.LogInformation("Saved resource registry with {Count} resource(s) to {Path}", resources.Count, storePath);
    }

    private static void ValidateNoDuplicates(IReadOnlyList<ProtectedResource> resources, string storePath)
    {
        var duplicateIds = resources.GroupBy(r => r.ResourceId, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicateIds is not null)
        {
            throw new ResourceRegistryCorruptException($"Resource registry '{storePath}' contains duplicate ResourceId '{duplicateIds.Key}'.");
        }

        foreach (var resource in resources)
        {
            if (string.IsNullOrWhiteSpace(resource.ResourceId) || string.IsNullOrWhiteSpace(resource.Destination))
            {
                throw new ResourceRegistryCorruptException($"Resource registry '{storePath}' contains a record with a missing required field.");
            }
        }
    }
}
