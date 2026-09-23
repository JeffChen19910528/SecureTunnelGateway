using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Firewall;

public sealed class PolicyService : IPolicyService
{
    private readonly IPolicyRepository _repository;
    private readonly IPeerService _peerService;
    private readonly IResourceService _resourceService;
    private readonly ILogger<PolicyService> _logger;

    public PolicyService(IPolicyRepository repository, IPeerService peerService, IResourceService resourceService, ILogger<PolicyService> logger)
    {
        _repository = repository;
        _peerService = peerService;
        _resourceService = resourceService;
        _logger = logger;
    }

    public Task<IReadOnlyList<AccessPolicy>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default) =>
        _repository.LoadAllAsync(config.PolicyStorePath, cancellationToken);

    public async Task<AccessPolicy?> GetAsync(GatewayConfiguration config, string ruleId, CancellationToken cancellationToken = default)
    {
        var policies = await _repository.LoadAllAsync(config.PolicyStorePath, cancellationToken);
        return policies.FirstOrDefault(p => string.Equals(p.RuleId, ruleId, StringComparison.Ordinal));
    }

    public async Task<PolicyOperationResult> AddAsync(GatewayConfiguration config, string peerId, string resourceId, string? description, bool dryRun, CancellationToken cancellationToken = default)
    {
        var policy = new AccessPolicy
        {
            RuleId = $"rule-{Guid.NewGuid():N}"[..13],
            PeerId = peerId?.Trim() ?? string.Empty,
            ResourceId = resourceId?.Trim() ?? string.Empty,
            Description = description,
            Enabled = true,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        IReadOnlyList<Peer> peers;
        IReadOnlyList<ProtectedResource> resources;
        IReadOnlyList<AccessPolicy> existingPolicies;
        try
        {
            peers = await _peerService.ListAsync(config, cancellationToken);
            resources = await _resourceService.ListAsync(config, cancellationToken);
            existingPolicies = await _repository.LoadAllAsync(config.PolicyStorePath, cancellationToken);
        }
        catch (Exception ex) when (ex is PeerRegistryCorruptException or ResourceRegistryCorruptException or PolicyRegistryCorruptException)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var validation = new ValidationResult();
        PolicyValidator.Validate(policy, peers, resources, validation);

        if (validation.IsValid && existingPolicies.Any(p =>
                string.Equals(p.PeerId, policy.PeerId, StringComparison.Ordinal) &&
                string.Equals(p.ResourceId, policy.ResourceId, StringComparison.Ordinal)))
        {
            validation.AddError("resourceId", $"A policy already grants peer '{policy.PeerId}' access to resource '{policy.ResourceId}'. Duplicate peer-to-resource permissions are not allowed.");
        }

        if (!validation.IsValid)
        {
            return new PolicyOperationResult
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
            return new PolicyOperationResult { Success = true, DryRun = true, Policy = policy, Issues = validation.Issues, Message = $"[DRY-RUN] Would add policy granting peer '{policy.PeerId}' access to resource '{policy.ResourceId}'. Nothing was persisted." };
        }

        var updated = existingPolicies.Append(policy).ToList();
        try
        {
            await _repository.SaveAllAsync(config.PolicyStorePath, updated, cancellationToken);
        }
        catch (PolicyRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Added policy {RuleId}: peer {PeerId} -> resource {ResourceId}", policy.RuleId, policy.PeerId, policy.ResourceId);
        return new PolicyOperationResult { Success = true, DryRun = false, Policy = policy, Issues = validation.Issues, Message = $"Added policy '{policy.RuleId}': peer '{policy.PeerId}' -> resource '{policy.ResourceId}'." };
    }

    public Task<PolicyOperationResult> EnableAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default) =>
        SetEnabledAsync(config, ruleId, enabled: true, dryRun, cancellationToken);

    public Task<PolicyOperationResult> DisableAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default) =>
        SetEnabledAsync(config, ruleId, enabled: false, dryRun, cancellationToken);

    public async Task<PolicyOperationResult> RemoveAsync(GatewayConfiguration config, string ruleId, bool dryRun, CancellationToken cancellationToken = default)
    {
        List<AccessPolicy> policies;
        try
        {
            policies = (await _repository.LoadAllAsync(config.PolicyStorePath, cancellationToken)).ToList();
        }
        catch (PolicyRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var existing = policies.FirstOrDefault(p => string.Equals(p.RuleId, ruleId, StringComparison.Ordinal));
        if (existing is null)
        {
            return new PolicyOperationResult { Success = false, DryRun = dryRun, FailureKind = PeerOperationFailureKind.NotFound, Message = $"No policy found with id '{ruleId}'." };
        }

        if (dryRun)
        {
            return new PolicyOperationResult { Success = true, DryRun = true, Policy = existing, Message = $"[DRY-RUN] Would remove policy '{ruleId}'. Nothing was persisted." };
        }

        policies.Remove(existing);
        try
        {
            await _repository.SaveAllAsync(config.PolicyStorePath, policies, cancellationToken);
        }
        catch (PolicyRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Removed policy {RuleId}", ruleId);
        return new PolicyOperationResult { Success = true, DryRun = false, Message = $"Removed policy '{ruleId}'." };
    }

    private async Task<PolicyOperationResult> SetEnabledAsync(GatewayConfiguration config, string ruleId, bool enabled, bool dryRun, CancellationToken cancellationToken)
    {
        List<AccessPolicy> policies;
        try
        {
            policies = (await _repository.LoadAllAsync(config.PolicyStorePath, cancellationToken)).ToList();
        }
        catch (PolicyRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var index = policies.FindIndex(p => string.Equals(p.RuleId, ruleId, StringComparison.Ordinal));
        if (index < 0)
        {
            return new PolicyOperationResult { Success = false, DryRun = dryRun, FailureKind = PeerOperationFailureKind.NotFound, Message = $"No policy found with id '{ruleId}'." };
        }

        var existing = policies[index];
        if (existing.Enabled == enabled)
        {
            return new PolicyOperationResult { Success = true, DryRun = dryRun, Policy = existing, Message = $"Policy '{ruleId}' is already {(enabled ? "enabled" : "disabled")}; no change." };
        }

        var updated = new AccessPolicy
        {
            RuleId = existing.RuleId,
            PeerId = existing.PeerId,
            ResourceId = existing.ResourceId,
            Description = existing.Description,
            Enabled = enabled,
            CreatedAtUtc = existing.CreatedAtUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };

        if (dryRun)
        {
            return new PolicyOperationResult { Success = true, DryRun = true, Policy = updated, Message = $"[DRY-RUN] Would set policy '{ruleId}' Enabled = {enabled}. Nothing was persisted." };
        }

        policies[index] = updated;
        try
        {
            await _repository.SaveAllAsync(config.PolicyStorePath, policies, cancellationToken);
        }
        catch (PolicyRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Policy {RuleId} Enabled -> {Enabled}", ruleId, enabled);
        return new PolicyOperationResult { Success = true, DryRun = false, Policy = updated, Message = $"Policy '{ruleId}' Enabled = {enabled}." };
    }

    private static PolicyOperationResult PersistenceFailure(bool dryRun, string message) => new()
    {
        Success = false,
        DryRun = dryRun,
        FailureKind = PeerOperationFailureKind.PersistenceFailed,
        Message = $"Policy registry error: {message}"
    };
}
