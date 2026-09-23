using Microsoft.Extensions.DependencyInjection;
using SecureTunnel.GatewayAgent.Services;

namespace SecureTunnel.GatewayAgent.Cli;

public static class ServiceProviderExtensions
{
    /// <summary>
    /// Creates a DI scope and, when <paramref name="dryRun"/> is true, marks it so that
    /// every service in the scope resolving <see cref="ISystemCommandExecutor"/> receives
    /// the dry-run decorator instead of the real executor. Must be called before any other
    /// service is resolved from the returned scope.
    /// </summary>
    public static IServiceScope CreateScope(this IServiceProvider services, bool dryRun)
    {
        var scope = services.CreateScope();
        scope.ServiceProvider.GetRequiredService<IDryRunContext>().IsDryRun = dryRun;
        return scope;
    }
}
