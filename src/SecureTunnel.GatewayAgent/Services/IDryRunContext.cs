namespace SecureTunnel.GatewayAgent.Services;

/// <summary>
/// Per-scope flag read by the ISystemCommandExecutor DI factory to decide whether to hand
/// out the real executor or the dry-run decorator. Set once, immediately after creating a
/// scope, before any other service in that scope is resolved - see
/// Cli/ServiceProviderExtensions.CreateScope(dryRun:).
/// </summary>
public sealed class DryRunContext : IDryRunContext
{
    public bool IsDryRun { get; set; }
}

public interface IDryRunContext
{
    bool IsDryRun { get; set; }
}
