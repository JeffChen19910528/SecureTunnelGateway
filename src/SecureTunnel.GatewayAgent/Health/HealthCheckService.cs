using Microsoft.Extensions.Logging;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.Validation;

namespace SecureTunnel.GatewayAgent.Health;

public sealed class HealthCheckService : IHealthCheckService
{
    private static readonly IReadOnlyDictionary<string, string> EnvironmentIdToHealthLabel = new Dictionary<string, string>
    {
        ["os.detected"] = "os",
        ["kernel.version"] = "kernel",
        ["wireguard.wg"] = "wireguard-command",
        ["wireguard.wg-quick"] = "wg-quick",
        ["wireguard.kernel-module"] = "wireguard-kernel-support",
        ["nftables.nft"] = "nftables-command",
        ["networking.ipv4-forward"] = "ip-forwarding",
        ["networking.interfaces"] = "network-interface",
        ["directories.config"] = "required-directories-config",
        ["directories.log"] = "required-directories-log",
        ["privileges.root"] = "root-permission",
        ["systemd.running"] = "systemd-availability"
    };

    private readonly IEnvironmentChecker _environmentChecker;
    private readonly IConfigurationLoader _configurationLoader;
    private readonly IConfigurationValidator _configurationValidator;
    private readonly IKeyManagementService _keyManagementService;
    private readonly ILogger<HealthCheckService> _logger;

    public HealthCheckService(
        IEnvironmentChecker environmentChecker,
        IConfigurationLoader configurationLoader,
        IConfigurationValidator configurationValidator,
        IKeyManagementService keyManagementService,
        ILogger<HealthCheckService> logger)
    {
        _environmentChecker = environmentChecker;
        _configurationLoader = configurationLoader;
        _configurationValidator = configurationValidator;
        _keyManagementService = keyManagementService;
        _logger = logger;
    }

    public async Task<HealthCheckReport> CheckAsync(string? configPath, CancellationToken cancellationToken = default)
    {
        var items = new List<HealthCheckItem>();

        try
        {
            var environmentResults = await _environmentChecker.RunChecksAsync(cancellationToken);
            foreach (var envResult in environmentResults)
            {
                if (EnvironmentIdToHealthLabel.TryGetValue(envResult.Id, out var label))
                {
                    items.Add(new HealthCheckItem(label, envResult.Status, envResult.Message));
                }
            }

            items.Add(CheckActiveConfigurationExistence(configPath));
            items.Add(CheckConfigurationValidity(configPath, out var loadedConfig));

            if (loadedConfig is not null)
            {
                items.Add(CheckKeyPermissions(loadedConfig));
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Health check failed unexpectedly");
            return new HealthCheckReport
            {
                OverallStatus = HealthStatus.Unknown,
                Items = new[] { new HealthCheckItem("health-check", CheckStatus.Blocked, $"Health check itself failed: {ex.Message}") },
                CheckedAtUtc = DateTimeOffset.UtcNow
            };
        }

        return new HealthCheckReport
        {
            OverallStatus = Aggregate(items),
            Items = items,
            CheckedAtUtc = DateTimeOffset.UtcNow
        };
    }

    private static HealthCheckItem CheckActiveConfigurationExistence(string? configPath)
    {
        if (string.IsNullOrWhiteSpace(configPath))
        {
            return new HealthCheckItem("active-configuration", CheckStatus.Warn, "No configuration path was provided.");
        }

        return File.Exists(configPath)
            ? new HealthCheckItem("active-configuration", CheckStatus.Pass, $"Configuration file found at '{configPath}'.")
            : new HealthCheckItem("active-configuration", CheckStatus.Fail, $"Configuration file '{configPath}' does not exist.");
    }

    private HealthCheckItem CheckConfigurationValidity(string? configPath, out GatewayConfiguration? loadedConfig)
    {
        loadedConfig = null;

        if (string.IsNullOrWhiteSpace(configPath) || !File.Exists(configPath))
        {
            return new HealthCheckItem("configuration-validity", CheckStatus.Blocked, "No configuration file available to validate.");
        }

        try
        {
            loadedConfig = _configurationLoader.Load(configPath);
        }
        catch (Exception ex)
        {
            return new HealthCheckItem("configuration-validity", CheckStatus.Fail, $"Failed to parse configuration: {ex.Message}");
        }

        var validation = _configurationValidator.Validate(loadedConfig);
        if (!validation.IsValid)
        {
            var firstError = validation.Errors.First();
            return new HealthCheckItem("configuration-validity", CheckStatus.Fail,
                $"Configuration failed validation ({validation.Errors.Count()} error(s)); first: {firstError}");
        }

        if (validation.Warnings.Any())
        {
            return new HealthCheckItem("configuration-validity", CheckStatus.Warn,
                $"Configuration is valid with {validation.Warnings.Count()} warning(s); first: {validation.Warnings.First()}");
        }

        return new HealthCheckItem("configuration-validity", CheckStatus.Pass, "Configuration passed validation.");
    }

    private HealthCheckItem CheckKeyPermissions(GatewayConfiguration config)
    {
        var check = _keyManagementService.CheckPrivateKeyPermissions(config.WireGuard.PrivateKeyPath);

        if (!check.Exists)
        {
            return new HealthCheckItem("key-file-permissions", CheckStatus.Warn, check.Message ?? "Private key not found.");
        }

        return check.PermissionsOk
            ? new HealthCheckItem("key-file-permissions", CheckStatus.Pass, check.Message ?? "Permissions OK.")
            : new HealthCheckItem("key-file-permissions", CheckStatus.Fail, check.Message ?? "Unsafe permissions.");
    }

    private static HealthStatus Aggregate(IReadOnlyList<HealthCheckItem> items)
    {
        if (items.Count == 0)
        {
            return HealthStatus.Unknown;
        }

        if (items.Any(i => i.Status == CheckStatus.Fail))
        {
            return HealthStatus.Unhealthy;
        }

        if (items.Any(i => i.Status is CheckStatus.Warn or CheckStatus.Blocked))
        {
            return HealthStatus.Degraded;
        }

        return HealthStatus.Healthy;
    }
}
