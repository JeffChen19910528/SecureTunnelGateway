using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class ResourceService : IResourceService
{
    private readonly IResourceRepository _repository;
    private readonly ILogger<ResourceService> _logger;

    public ResourceService(IResourceRepository repository, ILogger<ResourceService> logger)
    {
        _repository = repository;
        _logger = logger;
    }

    public Task<IReadOnlyList<ProtectedResource>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default) =>
        _repository.LoadAllAsync(config.ResourceStorePath, cancellationToken);

    public async Task<ProtectedResource?> GetAsync(GatewayConfiguration config, string resourceId, CancellationToken cancellationToken = default)
    {
        var resources = await _repository.LoadAllAsync(config.ResourceStorePath, cancellationToken);
        return resources.FirstOrDefault(r => string.Equals(r.ResourceId, resourceId, StringComparison.Ordinal));
    }

    public async Task<ResourceOperationResult> AddAsync(
        GatewayConfiguration config, string name, string destination, Protocol protocol, int port, int? portEnd,
        string? description, bool dryRun, CancellationToken cancellationToken = default)
    {
        var resource = new ProtectedResource
        {
            ResourceId = $"resource-{Guid.NewGuid():N}"[..17],
            Name = name?.Trim() ?? string.Empty,
            Description = description,
            Destination = destination?.Trim() ?? string.Empty,
            Protocol = protocol,
            Port = port,
            PortEnd = portEnd,
            Enabled = true,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        var validation = new ValidationResult();
        ResourceValidator.Validate(resource, validation);

        IReadOnlyList<ProtectedResource> existing;
        try
        {
            existing = await _repository.LoadAllAsync(config.ResourceStorePath, cancellationToken);
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        if (!validation.IsValid)
        {
            return new ResourceOperationResult
            {
                Success = false,
                DryRun = dryRun,
                FailureKind = PeerOperationFailureKind.ValidationFailed,
                Issues = validation.Issues,
                Message = $"Validation failed: {string.Join("; ", validation.Errors.Select(e => e.Message))}"
            };
        }

        if (dryRun)
        {
            return new ResourceOperationResult { Success = true, DryRun = true, Resource = resource, Message = $"[DRY-RUN] Would add resource '{resource.Name}'. Nothing was persisted." };
        }

        var updated = existing.Append(resource).ToList();
        try
        {
            await _repository.SaveAllAsync(config.ResourceStorePath, updated, cancellationToken);
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Added resource {ResourceId} ({Name})", resource.ResourceId, resource.Name);
        return new ResourceOperationResult { Success = true, DryRun = false, Resource = resource, Message = $"Added resource '{resource.Name}' ({resource.ResourceId})." };
    }

    public Task<ResourceOperationResult> EnableAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default) =>
        SetEnabledAsync(config, resourceId, enabled: true, dryRun, cancellationToken);

    public Task<ResourceOperationResult> DisableAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default) =>
        SetEnabledAsync(config, resourceId, enabled: false, dryRun, cancellationToken);

    public async Task<ResourceOperationResult> RemoveAsync(GatewayConfiguration config, string resourceId, bool dryRun, CancellationToken cancellationToken = default)
    {
        List<ProtectedResource> resources;
        try
        {
            resources = (await _repository.LoadAllAsync(config.ResourceStorePath, cancellationToken)).ToList();
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var existing = resources.FirstOrDefault(r => string.Equals(r.ResourceId, resourceId, StringComparison.Ordinal));
        if (existing is null)
        {
            return new ResourceOperationResult { Success = false, DryRun = dryRun, FailureKind = PeerOperationFailureKind.NotFound, Message = $"No resource found with id '{resourceId}'." };
        }

        if (dryRun)
        {
            return new ResourceOperationResult { Success = true, DryRun = true, Resource = existing, Message = $"[DRY-RUN] Would remove resource '{resourceId}'. Nothing was persisted." };
        }

        resources.Remove(existing);
        try
        {
            await _repository.SaveAllAsync(config.ResourceStorePath, resources, cancellationToken);
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Removed resource {ResourceId}", resourceId);
        return new ResourceOperationResult { Success = true, DryRun = false, Message = $"Removed resource '{resourceId}'." };
    }

    private async Task<ResourceOperationResult> SetEnabledAsync(GatewayConfiguration config, string resourceId, bool enabled, bool dryRun, CancellationToken cancellationToken)
    {
        List<ProtectedResource> resources;
        try
        {
            resources = (await _repository.LoadAllAsync(config.ResourceStorePath, cancellationToken)).ToList();
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var index = resources.FindIndex(r => string.Equals(r.ResourceId, resourceId, StringComparison.Ordinal));
        if (index < 0)
        {
            return new ResourceOperationResult { Success = false, DryRun = dryRun, FailureKind = PeerOperationFailureKind.NotFound, Message = $"No resource found with id '{resourceId}'." };
        }

        var existing = resources[index];
        if (existing.Enabled == enabled)
        {
            return new ResourceOperationResult { Success = true, DryRun = dryRun, Resource = existing, Message = $"Resource '{resourceId}' is already {(enabled ? "enabled" : "disabled")}; no change." };
        }

        var updated = new ProtectedResource
        {
            ResourceId = existing.ResourceId,
            Name = existing.Name,
            Description = existing.Description,
            Destination = existing.Destination,
            Protocol = existing.Protocol,
            Port = existing.Port,
            PortEnd = existing.PortEnd,
            Enabled = enabled,
            CreatedAtUtc = existing.CreatedAtUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        if (dryRun)
        {
            return new ResourceOperationResult { Success = true, DryRun = true, Resource = updated, Message = $"[DRY-RUN] Would set resource '{resourceId}' Enabled = {enabled}. Nothing was persisted." };
        }

        resources[index] = updated;
        try
        {
            await _repository.SaveAllAsync(config.ResourceStorePath, resources, cancellationToken);
        }
        catch (ResourceRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Resource {ResourceId} Enabled -> {Enabled}", resourceId, enabled);
        return new ResourceOperationResult { Success = true, DryRun = false, Resource = updated, Message = $"Resource '{resourceId}' Enabled = {enabled}." };
    }

    private static ResourceOperationResult PersistenceFailure(bool dryRun, string message) => new()
    {
        Success = false,
        DryRun = dryRun,
        FailureKind = PeerOperationFailureKind.PersistenceFailed,
        Message = $"Resource registry error: {message}"
    };
}
