using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.Security;

public sealed class KeyManagementService : IKeyManagementService
{
    private const UnixFileMode OwnerReadWrite = UnixFileMode.UserRead | UnixFileMode.UserWrite;

    private readonly ISystemCommandExecutor _executor;
    private readonly ILogger<KeyManagementService> _logger;

    public KeyManagementService(ISystemCommandExecutor executor, ILogger<KeyManagementService> logger)
    {
        _executor = executor;
        _logger = logger;
    }

    public async Task<KeyGenerationResult> GenerateServerKeyPairAsync(
        string privateKeyPath,
        string publicKeyPath,
        KeyGenerationOptions options,
        CancellationToken cancellationToken = default)
    {
        if (File.Exists(privateKeyPath) && !options.Force)
        {
            return new KeyGenerationResult
            {
                Success = false,
                DryRun = options.DryRun,
                Message = $"A server private key already exists at '{privateKeyPath}'. Refusing to overwrite it " +
                          "(all existing peers would lose connectivity). Re-run with --force to explicitly replace it."
            };
        }

        // wg --version does not require root and does not mutate anything, so it is safe
        // to run even under dry-run - it only checks the tool is present.
        var versionCheck = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "--version" },
            Timeout = TimeSpan.FromSeconds(5)
        }, cancellationToken);

        if (!versionCheck.Success)
        {
            return new KeyGenerationResult
            {
                Success = false,
                DryRun = options.DryRun,
                Message = "BLOCKED: 'wg' command not found or not runnable. Install wireguard-tools first " +
                          "(sudo apt-get install -y wireguard-tools) - see docs/installation-guide.md."
            };
        }

        if (options.DryRun)
        {
            return new KeyGenerationResult
            {
                Success = true,
                DryRun = true,
                Message = $"[DRY-RUN] Would generate a new WireGuard server key pair and write private key to " +
                          $"'{privateKeyPath}' (mode 0600) and public key to '{publicKeyPath}'. No files were written."
            };
        }

        var genKeyResult = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "genkey" },
            Timeout = TimeSpan.FromSeconds(10),
            SensitiveOutput = true
        }, cancellationToken);

        if (!genKeyResult.Success)
        {
            _logger.LogError("wg genkey failed with exit code {ExitCode}", genKeyResult.ExitCode);
            return new KeyGenerationResult
            {
                Success = false,
                DryRun = false,
                Message = "Failed to generate a private key ('wg genkey' did not succeed). See application log for exit code (key material is never logged)."
            };
        }

        var privateKey = new SensitiveString(genKeyResult.StandardOutput.Trim());

        var pubKeyResult = await _executor.ExecuteAsync(new CommandExecutionRequest
        {
            Command = "wg",
            Arguments = new[] { "pubkey" },
            StandardInput = privateKey.Reveal(),
            Timeout = TimeSpan.FromSeconds(10),
            SensitiveOutput = true
        }, cancellationToken);

        if (!pubKeyResult.Success)
        {
            _logger.LogError("wg pubkey failed with exit code {ExitCode}", pubKeyResult.ExitCode);
            return new KeyGenerationResult
            {
                Success = false,
                DryRun = false,
                Message = "Failed to derive the public key ('wg pubkey' did not succeed)."
            };
        }

        var publicKey = pubKeyResult.StandardOutput.Trim();

        try
        {
            var directory = Path.GetDirectoryName(privateKeyPath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(privateKeyPath, privateKey.Reveal() + Environment.NewLine, cancellationToken);
            ApplyOwnerOnlyPermissions(privateKeyPath);

            await File.WriteAllTextAsync(publicKeyPath, publicKey + Environment.NewLine, cancellationToken);
        }
        catch (Exception ex)
        {
            // Deliberately do not include exception details that might echo file content;
            // Exception.Message from a file-system failure describes the path, not key material.
            _logger.LogError(ex, "Failed to write generated key files to disk");
            return new KeyGenerationResult
            {
                Success = false,
                DryRun = false,
                Message = $"Key pair was generated but could not be written to disk: {ex.Message}"
            };
        }

        _logger.LogInformation("Generated new WireGuard server key pair. Public key: {PublicKey}", publicKey);

        return new KeyGenerationResult
        {
            Success = true,
            DryRun = false,
            PublicKey = publicKey,
            PrivateKeyPath = privateKeyPath,
            PublicKeyPath = publicKeyPath,
            Message = $"Generated new server key pair. Private key written to '{privateKeyPath}' (mode 0600)."
        };
    }

    public async Task<string?> ReadPublicKeyAsync(string publicKeyPath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(publicKeyPath))
        {
            return null;
        }

        var content = await File.ReadAllTextAsync(publicKeyPath, cancellationToken);
        return content.Trim();
    }

    public KeyPermissionCheckResult CheckPrivateKeyPermissions(string privateKeyPath)
    {
        if (!File.Exists(privateKeyPath))
        {
            return new KeyPermissionCheckResult
            {
                Exists = false,
                PermissionsOk = false,
                Message = $"Private key file '{privateKeyPath}' does not exist."
            };
        }

        if (OperatingSystem.IsWindows())
        {
            return new KeyPermissionCheckResult
            {
                Exists = true,
                PermissionsOk = false,
                Message = "Cannot verify Unix file permissions on Windows. This check is only meaningful on the target Linux host."
            };
        }

        var mode = File.GetUnixFileMode(privateKeyPath);
        var extraBits = mode & ~OwnerReadWrite;

        if (extraBits != UnixFileMode.None)
        {
            return new KeyPermissionCheckResult
            {
                Exists = true,
                PermissionsOk = false,
                Message = $"Private key file '{privateKeyPath}' has permissions {FormatMode(mode)}, expected 0600 or stricter (owner read/write only)."
            };
        }

        return new KeyPermissionCheckResult
        {
            Exists = true,
            PermissionsOk = true,
            Message = $"Private key file permissions are {FormatMode(mode)} (owner-only)."
        };
    }

    private void ApplyOwnerOnlyPermissions(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            _logger.LogWarning("Running on Windows: cannot set Unix owner-only file permissions for {Path}. " +
                                "This must be verified on the target Linux host.", path);
            return;
        }

        File.SetUnixFileMode(path, OwnerReadWrite);
    }

    private static string FormatMode(UnixFileMode mode)
    {
        int owner = ((mode & UnixFileMode.UserRead) != 0 ? 4 : 0)
                  + ((mode & UnixFileMode.UserWrite) != 0 ? 2 : 0)
                  + ((mode & UnixFileMode.UserExecute) != 0 ? 1 : 0);
        int group = ((mode & UnixFileMode.GroupRead) != 0 ? 4 : 0)
                  + ((mode & UnixFileMode.GroupWrite) != 0 ? 2 : 0)
                  + ((mode & UnixFileMode.GroupExecute) != 0 ? 1 : 0);
        int other = ((mode & UnixFileMode.OtherRead) != 0 ? 4 : 0)
                  + ((mode & UnixFileMode.OtherWrite) != 0 ? 2 : 0)
                  + ((mode & UnixFileMode.OtherExecute) != 0 ? 1 : 0);
        return $"0{owner}{group}{other}";
    }
}
