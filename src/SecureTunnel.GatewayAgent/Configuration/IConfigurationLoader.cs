using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Configuration;

public interface IConfigurationLoader
{
    GatewayConfiguration Load(string path);
}
