using SecureTunnel.GatewayAgent.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecureTunnel.GatewayAgent.Configuration;

/// <summary>
/// Loads config/gateway.yaml (camelCase keys, see config/gateway.example.yaml) into a
/// <see cref="GatewayConfiguration"/>. Deliberately does not validate - that is
/// <see cref="Validation.IConfigurationValidator"/>'s job, so loading and validation
/// stay independently testable.
/// </summary>
public sealed class YamlConfigurationLoader : IConfigurationLoader
{
    private readonly IDeserializer _deserializer = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        .IgnoreUnmatchedProperties()
        .Build();

    public GatewayConfiguration Load(string path)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Gateway configuration file not found: {path}", path);
        }

        var yaml = File.ReadAllText(path);
        var config = _deserializer.Deserialize<GatewayConfiguration>(yaml);
        return config ?? throw new InvalidDataException($"Gateway configuration file '{path}' is empty or invalid.");
    }
}
