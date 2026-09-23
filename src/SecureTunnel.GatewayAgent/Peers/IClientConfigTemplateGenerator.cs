using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Peers;

public sealed class ClientConfigTemplateResult
{
    public required bool Success { get; init; }
    public string? RenderedTemplate { get; init; }

    /// <summary>
    /// Always false in Phase 3: the Gateway never generates or holds a Client private
    /// key, so the rendered output is always a TEMPLATE the operator must complete
    /// (replace the PrivateKey placeholder with a key generated on the Client), never a
    /// complete usable configuration. See docs/configuration-guide.md "Client 設定範本".
    /// </summary>
    public required bool IsCompleteUsableConfig { get; init; }

    public string? Message { get; init; }
}

/// <summary>
/// Renders a Client-side WireGuard configuration TEMPLATE for a given Peer. Distinct from
/// <see cref="WireGuard.IWireGuardConfigGenerator"/>, which renders the SERVER's own
/// interface configuration - this type never touches the server private key and never
/// fabricates a client private key (see docs/security-model.md 第一節).
/// </summary>
public interface IClientConfigTemplateGenerator
{
    Task<ClientConfigTemplateResult> GenerateAsync(GatewayConfiguration config, Peer peer, CancellationToken cancellationToken = default);
}
