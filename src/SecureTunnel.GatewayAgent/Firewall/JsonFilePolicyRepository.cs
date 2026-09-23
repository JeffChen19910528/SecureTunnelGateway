using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Firewall;

/// <summary>Access Policy registry - same persistence design as JsonFileResourceRepository/JsonFilePeerRepository.</summary>
public sealed class JsonFilePolicyRepository : IPolicyRepository
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly ILogger<JsonFilePolicyRepository> _logger;

    public JsonFilePolicyRepository(ILogger<JsonFilePolicyRepository> logger)
    {
        _logger = logger;
    }

    public async Task<IReadOnlyList<AccessPolicy>> LoadAllAsync(string storePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(storePath))
        {
            return Array.Empty<AccessPolicy>();
        }

        string json;
        try
        {
            json = await File.ReadAllTextAsync(storePath, cancellationToken);
        }
        catch (IOException ex)
        {
            throw new PolicyRegistryCorruptException($"Could not read policy registry '{storePath}': {ex.Message}");
        }

        if (string.IsNullOrWhiteSpace(json))
        {
            throw new PolicyRegistryCorruptException($"Policy registry '{storePath}' exists but is empty. Refusing to treat this as an empty registry.");
        }

        List<AccessPolicy>? policies;
        try
        {
            policies = JsonSerializer.Deserialize<List<AccessPolicy>>(json, SerializerOptions);
        }
        catch (JsonException ex)
        {
            throw new PolicyRegistryCorruptException($"Policy registry '{storePath}' contains invalid JSON: {ex.Message}");
        }

        if (policies is null)
        {
            throw new PolicyRegistryCorruptException($"Policy registry '{storePath}' deserialized to null.");
        }

        ValidateNoDuplicates(policies, storePath);
        return policies;
    }

    public async Task SaveAllAsync(string storePath, IReadOnlyList<AccessPolicy> policies, CancellationToken cancellationToken = default)
    {
        ValidateNoDuplicates(policies, storePath);

        var directory = Path.GetDirectoryName(storePath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var tempPath = storePath + $".tmp-{Guid.NewGuid():N}";
        var json = JsonSerializer.Serialize(policies, SerializerOptions);
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

        _logger.LogInformation("Saved policy registry with {Count} polic(ies) to {Path}", policies.Count, storePath);
    }

    private static void ValidateNoDuplicates(IReadOnlyList<AccessPolicy> policies, string storePath)
    {
        var duplicateIds = policies.GroupBy(p => p.RuleId, StringComparer.Ordinal).FirstOrDefault(g => g.Count() > 1);
        if (duplicateIds is not null)
        {
            throw new PolicyRegistryCorruptException($"Policy registry '{storePath}' contains duplicate RuleId '{duplicateIds.Key}'.");
        }

        var duplicatePermissions = policies
            .GroupBy(p => (p.PeerId, p.ResourceId))
            .FirstOrDefault(g => g.Count() > 1);
        if (duplicatePermissions is not null)
        {
            throw new PolicyRegistryCorruptException(
                $"Policy registry '{storePath}' contains duplicate permission: peer '{duplicatePermissions.Key.PeerId}' -> " +
                $"resource '{duplicatePermissions.Key.ResourceId}' appears in more than one rule ({string.Join(", ", duplicatePermissions.Select(p => p.RuleId))}).");
        }

        foreach (var policy in policies)
        {
            if (string.IsNullOrWhiteSpace(policy.RuleId) || string.IsNullOrWhiteSpace(policy.PeerId) || string.IsNullOrWhiteSpace(policy.ResourceId))
            {
                throw new PolicyRegistryCorruptException($"Policy registry '{storePath}' contains a record with a missing required field.");
            }
        }
    }
}
