using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Backup;

/// <summary>
/// Creates and restores operational backups: the Peer/Resource/Policy Registries,
/// Configuration History, gateway.yaml, and the WireGuard server key pair. See
/// docs/security-model.md "Backup Security" for why the server private key is included
/// (a backup that can't actually restore VPN identity isn't a disaster-recovery backup)
/// and how that risk is scoped (archive permissions, never printed/logged).
///
/// Restore deliberately does NOT touch the running WireGuard/nftables state or make
/// anything Active - it only replaces the Registry/history files (the "Desired" state
/// input), backing up whatever was there first. An explicit `config apply` afterward is
/// required to actually activate the restored data - see Lifecycle/IConfigurationLifecycleService.
/// </summary>
public interface IBackupService
{
    Task<BackupCreateResult> CreateAsync(GatewayConfiguration config, string configPath, string? outputPath, bool dryRun, CancellationToken cancellationToken = default);

    Task<IReadOnlyList<BackupListEntry>> ListAsync(GatewayConfiguration config, CancellationToken cancellationToken = default);

    Task<BackupRestoreResult> RestoreAsync(GatewayConfiguration config, string configPath, string archivePath, bool dryRun, CancellationToken cancellationToken = default);
}
