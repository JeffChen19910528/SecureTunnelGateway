using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Security;

/// <summary>
/// Manages the WireGuard server key pair. Client private keys are never handled here -
/// clients generate their own keys; the Gateway only ever stores client public keys
/// (see docs/security-model.md 第一節).
/// </summary>
public interface IKeyManagementService
{
    /// <summary>
    /// Generates a new server key pair via `wg genkey`/`wg pubkey` and writes the private
    /// key to <paramref name="privateKeyPath"/> with owner-only permissions. Refuses to
    /// overwrite an existing key unless <paramref name="options"/>.Force is set - see
    /// docs/security-model.md: "正式環境不應由 Gateway 隨意重新產生既有 Server key".
    /// </summary>
    Task<KeyGenerationResult> GenerateServerKeyPairAsync(string privateKeyPath, string publicKeyPath, KeyGenerationOptions options, CancellationToken cancellationToken = default);

    /// <summary>Reads the public key file (public keys are not sensitive).</summary>
    Task<string?> ReadPublicKeyAsync(string publicKeyPath, CancellationToken cancellationToken = default);

    /// <summary>
    /// Checks that the private key file exists and has owner-only permissions. Never
    /// returns or logs the key content.
    /// </summary>
    KeyPermissionCheckResult CheckPrivateKeyPermissions(string privateKeyPath);
}
