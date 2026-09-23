using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;

namespace SecureTunnel.GatewayAgent.Lifecycle;

public sealed class ConfigurationLifecycleService : IConfigurationLifecycleService
{
    private const int MaxRetainedVersions = 30;
    private static readonly TimeSpan DefaultLockTimeout = TimeSpan.FromSeconds(30);

    private readonly TimeSpan _lockTimeout;
    private readonly IConfigurationHistoryRepository _historyRepository;
    private readonly IOperationLockFactory _lockFactory;
    private readonly IPeerService _peerService;
    private readonly IResourceService _resourceService;
    private readonly IPolicyService _policyService;
    private readonly IConfigurationValidator _configurationValidator;
    private readonly IWireGuardConfigGenerator _wireGuardConfigGenerator;
    private readonly IWireGuardService _wireGuardService;
    private readonly IFirewallRuleGenerator _firewallRuleGenerator;
    private readonly IFirewallApplyOrchestrator _firewallApplyOrchestrator;
    private readonly IFirewallService _firewallService;
    private readonly ILogger<ConfigurationLifecycleService> _logger;

    public ConfigurationLifecycleService(
        IConfigurationHistoryRepository historyRepository,
        IOperationLockFactory lockFactory,
        IPeerService peerService,
        IResourceService resourceService,
        IPolicyService policyService,
        IConfigurationValidator configurationValidator,
        IWireGuardConfigGenerator wireGuardConfigGenerator,
        IWireGuardService wireGuardService,
        IFirewallRuleGenerator firewallRuleGenerator,
        IFirewallApplyOrchestrator firewallApplyOrchestrator,
        IFirewallService firewallService,
        ILogger<ConfigurationLifecycleService> logger,
        TimeSpan? lockTimeout = null)
    {
        _lockTimeout = lockTimeout ?? DefaultLockTimeout;
        _historyRepository = historyRepository;
        _lockFactory = lockFactory;
        _peerService = peerService;
        _resourceService = resourceService;
        _policyService = policyService;
        _configurationValidator = configurationValidator;
        _wireGuardConfigGenerator = wireGuardConfigGenerator;
        _wireGuardService = wireGuardService;
        _firewallRuleGenerator = firewallRuleGenerator;
        _firewallApplyOrchestrator = firewallApplyOrchestrator;
        _firewallService = firewallService;
        _logger = logger;
    }

    public Task<ConfigurationHistory> GetHistoryAsync(GatewayConfiguration config, CancellationToken cancellationToken = default) =>
        _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);

    public async Task<ConfigurationSnapshot?> GetVersionAsync(GatewayConfiguration config, int version, CancellationToken cancellationToken = default)
    {
        var history = await _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);
        return history.Versions.FirstOrDefault(v => v.Version == version);
    }

    public async Task<string?> DetectIncompleteOperationAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        ConfigurationHistory history;
        try
        {
            history = await _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);
        }
        catch (ConfigurationHistoryCorruptException ex)
        {
            return $"Configuration history is corrupt and could not be read: {ex.Message}";
        }

        if (history.Versions.Count == 0)
        {
            return null;
        }

        var last = history.Versions.OrderByDescending(v => v.Version).First();
        if (last.State is ConfigurationState.ApplyPending or ConfigurationState.Applying or ConfigurationState.RollbackPending)
        {
            return $"Version {last.Version} was left in state '{last.State}' - the Gateway Agent process was likely interrupted mid-operation " +
                   $"(started {last.CreatedAtUtc:u}). Effective system state cannot be assumed from this alone; run `securetunnel-gateway config verify` " +
                   "to check actual WireGuard/nftables state, then `config apply` or `config rollback <last known good version>` as appropriate.";
        }

        return null;
    }

    public async Task<ConfigurationVerifyResult> VerifyAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        var wgStatus = await _wireGuardService.GetStatusAsync(config.WireGuard.InterfaceName, cancellationToken);
        var fwStatus = await _firewallService.GetStatusAsync(cancellationToken);

        var wgUp = wgStatus.State == WireGuardInterfaceState.Up;
        var fwPresent = fwStatus.State == FirewallTableState.Present;
        var known = wgStatus.State != WireGuardInterfaceState.Unknown && fwStatus.State != FirewallTableState.Unknown;

        var message = known
            ? $"WireGuard: {(wgUp ? "up" : "not up")}. Firewall table: {(fwPresent ? "present" : "not present")}."
            : $"Effective state could not be fully determined. WireGuard: {wgStatus.Message} Firewall: {fwStatus.Message}";

        return new ConfigurationVerifyResult { WireGuardUp = wgUp, FirewallTablePresent = fwPresent, EffectiveStateKnown = known, Message = message };
    }

    public async Task<bool> IsDesiredStaleAsync(GatewayConfiguration config, CancellationToken cancellationToken = default)
    {
        ConfigurationHistory history;
        try
        {
            history = await _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);
        }
        catch (ConfigurationHistoryCorruptException)
        {
            return true; // can't prove it's NOT stale - fail toward "there are pending changes", never toward "all clear"
        }

        if (history.ActiveVersion is not { } activeVersion)
        {
            return true; // nothing has ever been applied - Desired trivially differs from a non-existent Active
        }

        var active = history.Versions.FirstOrDefault(v => v.Version == activeVersion);
        if (active is null)
        {
            return true;
        }

        IReadOnlyList<Peer> peers;
        IReadOnlyList<ProtectedResource> resources;
        IReadOnlyList<AccessPolicy> policies;
        try
        {
            peers = await _peerService.ListAsync(config, cancellationToken);
            resources = await _resourceService.ListAsync(config, cancellationToken);
            policies = await _policyService.ListAsync(config, cancellationToken);
        }
        catch (Exception ex) when (ex is PeerRegistryCorruptException or ResourceRegistryCorruptException or PolicyRegistryCorruptException)
        {
            return true;
        }

        var liveHash = SnapshotHasher.ComputeHash(peers, resources, policies);
        return !string.Equals(liveHash, active.ContentHash, StringComparison.Ordinal);
    }

    public async Task<ConfigurationApplyResult> ApplyAsync(GatewayConfiguration config, string sourceReason, bool dryRun, CancellationToken cancellationToken = default)
    {
        IReadOnlyList<Peer> peers;
        IReadOnlyList<ProtectedResource> resources;
        IReadOnlyList<AccessPolicy> policies;
        try
        {
            peers = await _peerService.ListAsync(config, cancellationToken);
            resources = await _resourceService.ListAsync(config, cancellationToken);
            policies = await _policyService.ListAsync(config, cancellationToken);
        }
        catch (Exception ex) when (ex is PeerRegistryCorruptException or ResourceRegistryCorruptException or PolicyRegistryCorruptException)
        {
            return Failed(ConfigurationState.ValidationFailed, dryRun, null, $"Could not load desired state: {ex.Message}", Array.Empty<ValidationIssue>());
        }

        return await BuildAndApplyAsync(config, peers, resources, policies, sourceReason, rollbackTarget: null, dryRun, cancellationToken);
    }

    public async Task<ConfigurationApplyResult> RollbackAsync(GatewayConfiguration config, int targetVersion, bool dryRun, CancellationToken cancellationToken = default)
    {
        ConfigurationHistory history;
        try
        {
            history = await _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);
        }
        catch (ConfigurationHistoryCorruptException ex)
        {
            return Failed(ConfigurationState.ValidationFailed, dryRun, null, $"Configuration history error: {ex.Message}", Array.Empty<ValidationIssue>());
        }

        var target = history.Versions.FirstOrDefault(v => v.Version == targetVersion);
        if (target is null)
        {
            return Failed(ConfigurationState.ValidationFailed, dryRun, null, $"No configuration version {targetVersion} found.", Array.Empty<ValidationIssue>());
        }

        if (target.State is not (ConfigurationState.Active or ConfigurationState.Verified or ConfigurationState.RollbackSucceeded))
        {
            return Failed(ConfigurationState.ValidationFailed, dryRun, null,
                $"Version {targetVersion} was never successfully applied (recorded state: {target.State}). Refusing to roll back to an invalid target.",
                Array.Empty<ValidationIssue>());
        }

        // Rollback deliberately uses the snapshot's OWN embedded Peer/Resource/Policy data,
        // never the live (possibly since-changed) Registries - see docs/security-model.md
        // "Rollback must not depend on mutable current Registry data".
        return await BuildAndApplyAsync(config, target.Peers, target.Resources, target.Policies,
            $"rollback to v{targetVersion}", rollbackTarget: targetVersion, dryRun, cancellationToken);
    }

    private async Task<ConfigurationApplyResult> BuildAndApplyAsync(
        GatewayConfiguration config,
        IReadOnlyList<Peer> peers,
        IReadOnlyList<ProtectedResource> resources,
        IReadOnlyList<AccessPolicy> policies,
        string sourceReason,
        int? rollbackTarget,
        bool dryRun,
        CancellationToken cancellationToken)
    {
        var gatewayValidation = _configurationValidator.Validate(config);
        var effectivePeers = peers.Where(p => p.Status == PeerStatus.Active).ToList();

        var wgGeneration = await _wireGuardConfigGenerator.GenerateAsync(config, effectivePeers, new ConfigGenerationOptions { DryRun = true }, cancellationToken);
        var fwGeneration = await _firewallRuleGenerator.GenerateAsync(config, peers, resources, policies, new FirewallGenerationOptions { DryRun = true }, cancellationToken);

        // wgGeneration/fwGeneration each re-run GatewayConfigurationValidator internally
        // (defense-in-depth, same as their own standalone CLI commands), so the same
        // gateway.yaml-level issue can appear from more than one source here - de-duplicate
        // by rendered message so the operator sees each problem once, not three times.
        var allIssues = gatewayValidation.Issues
            .Concat(wgGeneration.ValidationIssues)
            .Concat(fwGeneration.ValidationIssues)
            .DistinctBy(i => (i.Field, i.Message))
            .ToList();

        ConfigurationHistory history;
        try
        {
            history = await _historyRepository.LoadAsync(config.ConfigurationHistoryPath, cancellationToken);
        }
        catch (ConfigurationHistoryCorruptException ex)
        {
            return Failed(ConfigurationState.ValidationFailed, dryRun, null, $"Configuration history error: {ex.Message}", allIssues);
        }

        var nextVersion = history.Versions.Count == 0 ? 1 : history.Versions.Max(v => v.Version) + 1;
        var snapshot = new ConfigurationSnapshot
        {
            Version = nextVersion,
            CreatedAtUtc = DateTimeOffset.UtcNow,
            SourceReason = sourceReason,
            ContentHash = SnapshotHasher.ComputeHash(peers, resources, policies),
            State = ConfigurationState.CandidateGenerated,
            Peers = peers,
            Resources = resources,
            Policies = policies,
            EffectiveWireGuardPeerCount = effectivePeers.Count,
            EffectiveFirewallRuleCount = fwGeneration.EffectiveRules.Count,
            RollbackTargetVersion = rollbackTarget,
            PreviousActiveVersion = history.ActiveVersion
        };

        var isValid = gatewayValidation.IsValid && wgGeneration.Success && fwGeneration.Success;
        if (!isValid)
        {
            snapshot.State = ConfigurationState.ValidationFailed;
            snapshot.FailureReason = string.Join("; ", allIssues.Where(i => i.Severity == ValidationSeverity.Error).Select(i => i.Message));
            await PersistAsync(config, history, snapshot, cancellationToken);
            return Failed(ConfigurationState.ValidationFailed, dryRun, snapshot.Version, $"Validation failed: {snapshot.FailureReason}", allIssues);
        }

        snapshot.State = ConfigurationState.Validated;

        if (dryRun)
        {
            return new ConfigurationApplyResult
            {
                Success = true,
                DryRun = true,
                State = ConfigurationState.Validated,
                Version = snapshot.Version,
                Message = $"[DRY-RUN] Candidate v{snapshot.Version} validated ({snapshot.EffectiveWireGuardPeerCount} WireGuard peer(s), " +
                          $"{snapshot.EffectiveFirewallRuleCount} firewall rule(s)). Nothing was applied or persisted.",
                ValidationIssues = allIssues
            };
        }

        using var operationLock = await _lockFactory.AcquireAsync(config.OperationLockPath, _lockTimeout, cancellationToken);
        if (!operationLock.Acquired)
        {
            snapshot.State = ConfigurationState.ApplyFailed;
            snapshot.FailureReason = operationLock.Message;
            await PersistAsync(config, history, snapshot, cancellationToken);
            return Failed(ConfigurationState.ApplyFailed, false, snapshot.Version, operationLock.Message ?? "Could not acquire operation lock.", allIssues);
        }

        snapshot.State = ConfigurationState.ApplyPending;
        await PersistAsync(config, history, snapshot, cancellationToken); // checkpoint: recorded BEFORE touching the system

        snapshot.State = ConfigurationState.Applying;
        await PersistAsync(config, history, snapshot, cancellationToken); // checkpoint: recorded BEFORE the first mutating call

        var wireGuardOutcome = await ApplyWireGuardAsync(config, effectivePeers, cancellationToken);
        snapshot.WireGuardApplied = wireGuardOutcome.Success;

        if (!wireGuardOutcome.Success)
        {
            snapshot.State = ConfigurationState.ApplyFailed;
            snapshot.FailureReason = $"WireGuard apply failed: {wireGuardOutcome.Message}";
            await PersistAsync(config, history, snapshot, cancellationToken);
            return Failed(ConfigurationState.ApplyFailed, false, snapshot.Version, snapshot.FailureReason, allIssues);
        }

        var firewallOutcome = await _firewallApplyOrchestrator.ApplyAsync(config, peers, resources, policies, dryRun: false, cancellationToken);
        snapshot.FirewallApplied = firewallOutcome.Success;

        if (!firewallOutcome.Success)
        {
            // Partial failure: WireGuard succeeded, nftables did not. FirewallApplyOrchestrator
            // already restored its own last-known-good ruleset on failure (see Firewall/FirewallApplyOrchestrator.cs),
            // so the effective firewall state should still be the PREVIOUS (safe, default-deny)
            // ruleset - which simply does not yet grant access to whatever changed in this
            // candidate. This is a safe-by-construction degraded state, not an open one, but we
            // still refuse to call it Active or a clean failure - see docs/security-model.md.
            snapshot.State = ConfigurationState.EffectiveStateUnknown;
            snapshot.FailureReason = $"WireGuard applied successfully, but nftables apply failed: {firewallOutcome.Message} " +
                                     "(the previous firewall ruleset, if any, was restored - this does not grant unintended access, " +
                                     "but the new WireGuard peer set and firewall rule set are now out of sync).";
            await PersistAsync(config, history, snapshot, cancellationToken);
            return Failed(ConfigurationState.EffectiveStateUnknown, false, snapshot.Version, snapshot.FailureReason, allIssues);
        }

        snapshot.State = ConfigurationState.Applied;

        var verify = await VerifyAsync(config, cancellationToken);
        if (!verify.EffectiveStateKnown || !verify.WireGuardUp || !verify.FirewallTablePresent)
        {
            snapshot.State = verify.EffectiveStateKnown ? ConfigurationState.VerificationFailed : ConfigurationState.EffectiveStateUnknown;
            snapshot.FailureReason = verify.Message;
            await PersistAsync(config, history, snapshot, cancellationToken);
            return Failed(snapshot.State, false, snapshot.Version, verify.Message, allIssues);
        }

        snapshot.State = rollbackTarget.HasValue ? ConfigurationState.RollbackSucceeded : ConfigurationState.Active;
        history.ActiveVersion = snapshot.Version;
        if (snapshot.PreviousActiveVersion.HasValue)
        {
            history.LastKnownGoodVersion = snapshot.PreviousActiveVersion;
        }

        await PersistAsync(config, history, snapshot, cancellationToken);

        _logger.LogInformation("Configuration version {Version} is now Active ({WgPeers} WireGuard peer(s), {FwRules} firewall rule(s)).",
            snapshot.Version, snapshot.EffectiveWireGuardPeerCount, snapshot.EffectiveFirewallRuleCount);

        return new ConfigurationApplyResult
        {
            Success = true,
            DryRun = false,
            State = snapshot.State,
            Version = snapshot.Version,
            Message = $"Version {snapshot.Version} applied and verified " +
                      $"({snapshot.EffectiveWireGuardPeerCount} WireGuard peer(s), {snapshot.EffectiveFirewallRuleCount} firewall rule(s)).",
            ValidationIssues = allIssues
        };
    }

    /// <summary>
    /// Writes the WireGuard interface config (backing up the previous one first) and
    /// (re)starts the interface. On restart failure, attempts to restore the previous
    /// config and bring the interface back up with it - best-effort recovery mirroring
    /// Firewall/FirewallApplyOrchestrator's restore-on-failure pattern.
    /// </summary>
    private async Task<(bool Success, string Message)> ApplyWireGuardAsync(GatewayConfiguration config, IReadOnlyList<Peer> effectivePeers, CancellationToken cancellationToken)
    {
        var activePath = config.WireGuard.ConfigOutputPath ?? $"/etc/wireguard/{config.WireGuard.InterfaceName}.conf";
        var backupPath = activePath + ".lastknowngood";
        var hadPreviousActive = File.Exists(activePath);

        if (hadPreviousActive)
        {
            try { File.Copy(activePath, backupPath, overwrite: true); }
            catch (Exception ex) { return (false, $"Failed to back up existing WireGuard config before writing candidate: {ex.Message}"); }
        }

        var generation = await _wireGuardConfigGenerator.GenerateAsync(config, effectivePeers,
            new ConfigGenerationOptions { Force = true, OutputPath = activePath }, cancellationToken);

        if (!generation.Success)
        {
            return (false, $"Failed to write WireGuard config: {string.Join("; ", generation.ValidationIssues.Select(i => i.Message))}");
        }

        var restart = await _wireGuardService.RestartAsync(config.WireGuard.InterfaceName, cancellationToken);
        if (restart.ExitCode == -1)
        {
            return (false, "BLOCKED: 'wg-quick' command not available on this host.");
        }

        if (restart.Success)
        {
            return (true, "WireGuard interface applied and restarted.");
        }

        // Restart failed with the new config - attempt to restore the previous one so
        // existing peers are not left disconnected any longer than necessary.
        if (hadPreviousActive)
        {
            try
            {
                File.Copy(backupPath, activePath, overwrite: true);
                var recoveryRestart = await _wireGuardService.RestartAsync(config.WireGuard.InterfaceName, cancellationToken);
                var recoveryNote = recoveryRestart.Success
                    ? "The previous WireGuard config was restored and the interface was brought back up."
                    : "Attempted to restore the previous WireGuard config, but the interface could not be restarted either - manual intervention required.";
                return (false, $"wg-quick restart failed with the new config: {restart.StandardError.Trim()}. {recoveryNote}");
            }
            catch (Exception ex)
            {
                return (false, $"wg-quick restart failed with the new config: {restart.StandardError.Trim()}. " +
                               $"Additionally failed to restore the previous config: {ex.Message}. Manual intervention required.");
            }
        }

        return (false, $"wg-quick restart failed: {restart.StandardError.Trim()}");
    }

    private async Task PersistAsync(GatewayConfiguration config, ConfigurationHistory history, ConfigurationSnapshot snapshot, CancellationToken cancellationToken)
    {
        if (!history.Versions.Any(v => v.Version == snapshot.Version))
        {
            history.Versions.Add(snapshot);
        }

        Prune(history);
        await _historyRepository.SaveAsync(config.ConfigurationHistoryPath, history, cancellationToken);
    }

    /// <summary>Keeps history bounded without ever discarding the Active or Last Known Good version - see docs/security-model.md "Last Known Good".</summary>
    private static void Prune(ConfigurationHistory history)
    {
        if (history.Versions.Count <= MaxRetainedVersions)
        {
            return;
        }

        var mustKeep = new HashSet<int?> { history.ActiveVersion, history.LastKnownGoodVersion };
        var ordered = history.Versions.OrderByDescending(v => v.Version).ToList();
        var kept = new List<ConfigurationSnapshot>();

        foreach (var v in ordered)
        {
            if (kept.Count < MaxRetainedVersions || mustKeep.Contains(v.Version))
            {
                kept.Add(v);
            }
        }

        history.Versions = kept.OrderBy(v => v.Version).ToList();
    }

    private static ConfigurationApplyResult Failed(ConfigurationState state, bool dryRun, int? version, string message, IReadOnlyList<ValidationIssue> issues) => new()
    {
        Success = false,
        DryRun = dryRun,
        State = state,
        Version = version,
        Message = message,
        ValidationIssues = issues
    };
}
