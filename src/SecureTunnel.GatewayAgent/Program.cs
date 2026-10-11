using System.CommandLine;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog;
using SecureTunnel.GatewayAgent.Cli;
using SecureTunnel.GatewayAgent.Configuration;
using SecureTunnel.GatewayAgent.Backup;
using SecureTunnel.GatewayAgent.Daemon;
using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Health;
using SecureTunnel.GatewayAgent.Lifecycle;
using SecureTunnel.GatewayAgent.Peers;
using SecureTunnel.GatewayAgent.Routing;
using SecureTunnel.GatewayAgent.Security;
using SecureTunnel.GatewayAgent.Services;
using SecureTunnel.GatewayAgent.Validation;
using SecureTunnel.GatewayAgent.WireGuard;

var services = BuildServiceProvider();
var root = RootCommandFactory.Build(services);
var exitCode = await root.Parse(args).InvokeAsync(new InvocationConfiguration
{
    // System.CommandLine's own SIGTERM/SIGINT handler races with the daemon's shutdown and throws
    // ObjectDisposedException on a disposed CancellationTokenSource after a graceful stop.
    // GatewayDaemonService registers SIGINT/SIGTERM itself, so the library handler is disabled.
    ProcessTerminationTimeout = null,
});
Log.CloseAndFlush();
return exitCode;

static IServiceProvider BuildServiceProvider()
{
    // Serilog: console only for now. Phase 2 keeps logging minimal and safe-by-default;
    // file sinks pointed at logging.applicationLogPath/auditLogPath are wired up once the
    // Configuration Lifecycle (Phase 5) determines where the active config actually lives.
    Log.Logger = new LoggerConfiguration()
        .MinimumLevel.Information()
        .WriteTo.Console(standardErrorFromLevel: Serilog.Events.LogEventLevel.Warning)
        .Enrich.FromLogContext()
        .CreateLogger();

    var collection = new ServiceCollection();

    collection.AddLogging(builder =>
    {
        builder.ClearProviders();
        builder.AddSerilog(dispose: false);
    });

    // Scoped so that IDryRunContext (also scoped) can steer which ISystemCommandExecutor
    // implementation each CLI invocation's scope receives. See Cli/ServiceProviderExtensions.
    collection.AddScoped<IDryRunContext, DryRunContext>();
    collection.AddScoped<SystemCommandExecutor>();
    collection.AddScoped<ISystemCommandExecutor>(sp =>
    {
        var real = sp.GetRequiredService<SystemCommandExecutor>();
        var dryRunContext = sp.GetRequiredService<IDryRunContext>();
        return dryRunContext.IsDryRun
            ? new DryRunSystemCommandExecutor(real, sp.GetRequiredService<ILogger<DryRunSystemCommandExecutor>>())
            : real;
    });

    collection.AddScoped<IEnvironmentChecker, EnvironmentChecker>();
    collection.AddScoped<IConfigurationLoader, YamlConfigurationLoader>();
    collection.AddScoped<IConfigurationValidator, GatewayConfigurationValidator>();
    collection.AddScoped<IKeyManagementService, KeyManagementService>();
    collection.AddScoped<IWireGuardConfigGenerator, WireGuardConfigGenerator>();
    collection.AddScoped<IWireGuardService, WireGuardService>();
    collection.AddScoped<IForwardingService, ForwardingService>();
    collection.AddScoped<IHealthCheckService, HealthCheckService>();

    collection.AddScoped<IPeerRepository, JsonFilePeerRepository>();
    collection.AddScoped<IVpnIpAllocator, Ipv4VpnIpAllocator>();
    collection.AddScoped<IPeerService, PeerService>();
    collection.AddScoped<IClientConfigTemplateGenerator, ClientConfigTemplateGenerator>();

    collection.AddScoped<IResourceRepository, JsonFileResourceRepository>();
    collection.AddScoped<IResourceService, ResourceService>();
    collection.AddScoped<IPolicyRepository, JsonFilePolicyRepository>();
    collection.AddScoped<IPolicyService, PolicyService>();
    collection.AddScoped<IFirewallRuleGenerator, FirewallRuleGenerator>();
    collection.AddScoped<IFirewallService, FirewallService>();
    collection.AddScoped<IFirewallApplyOrchestrator, FirewallApplyOrchestrator>();

    collection.AddScoped<IConfigurationHistoryRepository, JsonFileConfigurationHistoryRepository>();
    collection.AddScoped<IOperationLockFactory, FileOperationLockFactory>();
    collection.AddScoped<IConfigurationLifecycleService, ConfigurationLifecycleService>();
    collection.AddScoped<IBackupService, BackupService>();

    collection.AddScoped<IDaemonTicker, SystemDaemonTicker>();
    collection.AddScoped<IGatewayDaemonService, GatewayDaemonService>();

    return collection.BuildServiceProvider();
}

/// <summary>Marker type used for `ILogger&lt;Program&gt;` in top-level statements.</summary>
public partial class Program;
