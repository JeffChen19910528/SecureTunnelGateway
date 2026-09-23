using Xunit;

namespace SecureTunnel.GatewayAgent.IntegrationTests;

/// <summary>
/// Console.Out/Console.Error are process-wide statics. Any test class that redirects
/// them (CliInvocationTests, PeerCliInvocationTests) must run sequentially relative to
/// every other such class, or two tests running in parallel can capture each other's
/// output - xUnit runs different test classes in parallel by default, so without this
/// shared collection, output-assertion tests become flaky. Every class doing console
/// redirection must carry [Collection(Name)].
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class ConsoleRedirectionCollection
{
    public const string Name = "Console Redirection";
}
