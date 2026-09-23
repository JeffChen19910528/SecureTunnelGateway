using System.Text;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Security;

namespace SecureTunnel.GatewayAgent.Peers;

public sealed class ClientConfigTemplateGenerator : IClientConfigTemplateGenerator
{
    private const string PrivateKeyPlaceholder = "<INSERT_CLIENT_PRIVATE_KEY_HERE>";
    private const string EndpointPlaceholder = "<GATEWAY_PUBLIC_ENDPOINT>";

    private readonly IKeyManagementService _keyManagementService;

    public ClientConfigTemplateGenerator(IKeyManagementService keyManagementService)
    {
        _keyManagementService = keyManagementService;
    }

    public async Task<ClientConfigTemplateResult> GenerateAsync(GatewayConfiguration config, Peer peer, CancellationToken cancellationToken = default)
    {
        var serverPublicKey = await _keyManagementService.ReadPublicKeyAsync(config.WireGuard.PublicKeyPath, cancellationToken);
        if (serverPublicKey is null)
        {
            return new ClientConfigTemplateResult
            {
                Success = false,
                IsCompleteUsableConfig = false,
                Message = $"BLOCKED: server public key not found at '{config.WireGuard.PublicKeyPath}'. " +
                          "Run `securetunnel-gateway wireguard generate-keys` first."
            };
        }

        var endpointHost = string.IsNullOrWhiteSpace(config.WireGuard.EndpointHost)
            ? EndpointPlaceholder
            : config.WireGuard.EndpointHost;

        var allowedIps = new List<string> { config.Network.VpnCidr };
        allowedIps.AddRange(config.Network.ProtectedNetworks.Select(n => n.Cidr));

        var sb = new StringBuilder();
        sb.AppendLine("# SecureTunnel Gateway - Client Configuration TEMPLATE");
        sb.AppendLine("# This is a TEMPLATE, not a ready-to-use configuration.");
        sb.AppendLine("#");
        sb.AppendLine($"# 1. Replace {PrivateKeyPlaceholder} with a private key generated ON THE CLIENT");
        sb.AppendLine("#    device itself (e.g. run `wg genkey` there), or by an operator in a separate,");
        sb.AppendLine("#    controlled process. The Gateway never generates or stores Client private keys");
        sb.AppendLine("#    - see docs/security-model.md.");
        if (endpointHost == EndpointPlaceholder)
        {
            sb.AppendLine($"# 2. Replace {EndpointPlaceholder} with this Gateway's public hostname or IP");
            sb.AppendLine("#    (or set wireGuard.endpointHost in gateway.yaml and regenerate).");
        }
        sb.AppendLine($"#");
        sb.AppendLine($"# Peer: {peer.Name} ({peer.PeerId})");
        sb.AppendLine();
        sb.AppendLine("[Interface]");
        sb.AppendLine($"Address = {peer.AssignedVpnIp}/32");
        sb.AppendLine($"PrivateKey = {PrivateKeyPlaceholder}");
        sb.AppendLine();
        sb.AppendLine("[Peer]");
        sb.AppendLine($"PublicKey = {serverPublicKey}");
        sb.AppendLine($"Endpoint = {endpointHost}:{config.WireGuard.ListenPort}");
        sb.AppendLine($"AllowedIPs = {string.Join(", ", allowedIps)}");
        sb.AppendLine("PersistentKeepalive = 25");

        return new ClientConfigTemplateResult
        {
            Success = true,
            RenderedTemplate = sb.ToString(),
            IsCompleteUsableConfig = false,
            Message = "Template generated. Replace the PrivateKey placeholder on the Client device before use."
        };
    }
}
