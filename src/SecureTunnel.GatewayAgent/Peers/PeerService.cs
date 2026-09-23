using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

public sealed class PeerService : IPeerService
{
    private readonly IPeerRepository _repository;
    private readonly IVpnIpAllocator _allocator;
    private readonly ILogger<PeerService> _logger;

    public PeerService(IPeerRepository repository, IVpnIpAllocator allocator, ILogger<PeerService> logger)
    {
        _repository = repository;
        _allocator = allocator;
        _logger = logger;
    }

    public async Task<IReadOnlyList<Peer>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default) =>
        await LoadOrThrow(config, cancellationToken);

    public async Task<Peer?> GetAsync(GatewayConfiguration config, string peerId, CancellationToken cancellationToken = default)
    {
        var peers = await LoadOrThrow(config, cancellationToken);
        return peers.FirstOrDefault(p => string.Equals(p.PeerId, peerId, StringComparison.Ordinal));
    }

    public async Task<IReadOnlyList<Peer>> GetEffectivePeersAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        var peers = await LoadOrThrow(config, cancellationToken);
        return peers.Where(p => p.Status == PeerStatus.Active).ToList();
    }

    public async Task<PeerOperationResult> AddAsync(GatewayConfiguration config, string name, string publicKey, string? description, string? requestedVpnIp, bool dryRun, CancellationToken cancellationToken = default)
    {
        var issues = new List<ValidationIssue>();

        if (string.IsNullOrWhiteSpace(name) || name.Length > 100 || name.Any(char.IsControl))
        {
            issues.Add(new ValidationIssue("name", ValidationSeverity.Error, "Name must be non-empty, at most 100 characters, and contain no control characters."));
        }

        if (!WireGuardPublicKeyValidator.TryValidate(publicKey, out var keyError))
        {
            issues.Add(new ValidationIssue("publicKey", ValidationSeverity.Error, keyError!));
        }

        IReadOnlyList<Peer> peers;
        try
        {
            peers = await LoadOrThrow(config, cancellationToken);
        }
        catch (PeerRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        if (issues.Count == 0 && peers.Any(p => string.Equals(p.PublicKey, publicKey.Trim(), StringComparison.Ordinal)))
        {
            issues.Add(new ValidationIssue("publicKey", ValidationSeverity.Error,
                "This public key is already registered (including Disabled/Revoked/Removed peers - a revoked identity is never silently reused; remove the conflicting record first if this is intentional)."));
        }

        if (issues.Count > 0)
        {
            return ValidationFailure(dryRun, issues);
        }

        var allocation = _allocator.Allocate(config, peers, requestedVpnIp);
        if (!allocation.Success)
        {
            return ValidationFailure(dryRun, new[] { new ValidationIssue("vpnIp", ValidationSeverity.Error, allocation.Message) });
        }

        var peer = new Peer
        {
            PeerId = GeneratePeerId(),
            Name = name.Trim(),
            Description = description,
            PublicKey = publicKey.Trim(),
            AssignedVpnIp = allocation.AllocatedIp!,
            Status = PeerStatus.Active,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            AllowedIps = new List<string> { $"{allocation.AllocatedIp}/32" }
        };

        if (dryRun)
        {
            return new PeerOperationResult
            {
                Success = true,
                DryRun = true,
                Peer = peer,
                Message = $"[DRY-RUN] Would add peer '{peer.Name}' with VPN IP {peer.AssignedVpnIp}. Nothing was persisted."
            };
        }

        var updated = peers.Append(peer).ToList();
        try
        {
            await _repository.SaveAllAsync(config.PeerStorePath, updated, cancellationToken);
        }
        catch (PeerRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Added peer {PeerId} ({Name}) with VPN IP {VpnIp}", peer.PeerId, peer.Name, peer.AssignedVpnIp);

        return new PeerOperationResult { Success = true, DryRun = false, Peer = peer, Message = $"Added peer '{peer.Name}' ({peer.PeerId}) with VPN IP {peer.AssignedVpnIp}." };
    }

    public Task<PeerOperationResult> EnableAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default) =>
        TransitionAsync(config, peerId, dryRun, allowedFrom: new[] { PeerStatus.Pending, PeerStatus.Disabled }, target: PeerStatus.Active,
            revalidateIp: true, verb: "enable", cancellationToken);

    public Task<PeerOperationResult> DisableAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default) =>
        TransitionAsync(config, peerId, dryRun, allowedFrom: new[] { PeerStatus.Pending, PeerStatus.Active }, target: PeerStatus.Disabled,
            revalidateIp: false, verb: "disable", cancellationToken);

    public Task<PeerOperationResult> RevokeAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default) =>
        TransitionAsync(config, peerId, dryRun, allowedFrom: new[] { PeerStatus.Pending, PeerStatus.Active, PeerStatus.Disabled }, target: PeerStatus.Revoked,
            revalidateIp: false, verb: "revoke", cancellationToken);

    public Task<PeerOperationResult> RemoveAsync(GatewayConfiguration config, string peerId, bool dryRun, CancellationToken cancellationToken = default) =>
        TransitionAsync(config, peerId, dryRun, allowedFrom: new[] { PeerStatus.Pending, PeerStatus.Active, PeerStatus.Disabled, PeerStatus.Revoked }, target: PeerStatus.Removed,
            revalidateIp: false, verb: "remove", cancellationToken, idempotentFrom: PeerStatus.Removed);

    private async Task<PeerOperationResult> TransitionAsync(
        GatewayConfiguration config,
        string peerId,
        bool dryRun,
        PeerStatus[] allowedFrom,
        PeerStatus target,
        bool revalidateIp,
        string verb,
        CancellationToken cancellationToken,
        PeerStatus? idempotentFrom = null)
    {
        List<Peer> peers;
        try
        {
            peers = (await LoadOrThrow(config, cancellationToken)).ToList();
        }
        catch (PeerRegistryCorruptException ex)
        {
            return PersistenceFailure(dryRun, ex.Message);
        }

        var index = peers.FindIndex(p => string.Equals(p.PeerId, peerId, StringComparison.Ordinal));
        if (index < 0)
        {
            return new PeerOperationResult { Success = false, DryRun = dryRun, FailureKind = PeerOperationFailureKind.NotFound, Message = $"No peer found with id '{peerId}'." };
        }

        var existing = peers[index];

        if (idempotentFrom.HasValue && existing.Status == idempotentFrom.Value)
        {
            return new PeerOperationResult { Success = true, DryRun = dryRun, Peer = existing, Message = $"Peer '{peerId}' is already {existing.Status}; no change." };
        }

        if (!allowedFrom.Contains(existing.Status))
        {
            return new PeerOperationResult
            {
                Success = false,
                DryRun = dryRun,
                FailureKind = PeerOperationFailureKind.Conflict,
                Message = $"Cannot {verb} peer '{peerId}': current status is {existing.Status}, which does not allow this transition. " +
                          $"Allowed source statuses: {string.Join(", ", allowedFrom)}."
            };
        }

        if (revalidateIp && !_allocator.IsAvailable(config, peers, existing.AssignedVpnIp, excludePeerId: existing.PeerId))
        {
            return new PeerOperationResult
            {
                Success = false,
                DryRun = dryRun,
                FailureKind = PeerOperationFailureKind.Conflict,
                Message = $"Cannot {verb} peer '{peerId}': its VPN IP {existing.AssignedVpnIp} is no longer available (conflicts with Gateway/network/another peer)."
            };
        }

        var updatedPeer = new Peer
        {
            PeerId = existing.PeerId,
            Name = existing.Name,
            Description = existing.Description,
            PublicKey = existing.PublicKey,
            AssignedVpnIp = existing.AssignedVpnIp,
            Status = target,
            CreatedAtUtc = existing.CreatedAtUtc,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            LastHandshakeAtUtc = existing.LastHandshakeAtUtc,
            Endpoint = existing.Endpoint,
            AllowedIps = existing.AllowedIps,
            PersistentKeepaliveSeconds = existing.PersistentKeepaliveSeconds
        };

        if (dryRun)
        {
            return new PeerOperationResult { Success = true, DryRun = true, Peer = updatedPeer, Message = $"[DRY-RUN] Would {verb} peer '{peerId}' ({existing.Status} -> {target}). Nothing was persisted." };
        }

        peers[index] = updatedPeer;
        try
        {
            await _repository.SaveAllAsync(config.PeerStorePath, peers, cancellationToken);
        }
        catch (PeerRegistryCorruptException ex)
        {
            return PersistenceFailure(false, ex.Message);
        }

        _logger.LogInformation("Peer {PeerId} transitioned {From} -> {To}", peerId, existing.Status, target);

        return new PeerOperationResult { Success = true, DryRun = false, Peer = updatedPeer, Message = $"Peer '{peerId}' {existing.Status} -> {target}." };
    }

    private async Task<IReadOnlyList<Peer>> LoadOrThrow(GatewayConfiguration config, CancellationToken cancellationToken) =>
        await _repository.LoadAllAsync(config.PeerStorePath, cancellationToken);

    private static PeerOperationResult ValidationFailure(bool dryRun, IReadOnlyList<ValidationIssue> issues) => new()
    {
        Success = false,
        DryRun = dryRun,
        FailureKind = PeerOperationFailureKind.ValidationFailed,
        Issues = issues,
        Message = $"Validation failed: {string.Join("; ", issues.Select(i => i.Message))}"
    };

    private static PeerOperationResult PersistenceFailure(bool dryRun, string message) => new()
    {
        Success = false,
        DryRun = dryRun,
        FailureKind = PeerOperationFailureKind.PersistenceFailed,
        Message = $"Peer registry error: {message}"
    };

    private static string GeneratePeerId() => $"peer-{Guid.NewGuid():N}"[..17];
}
