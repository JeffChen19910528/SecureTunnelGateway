using SecureTunnel.GatewayAgent.Models;

namespace SecureTunnel.GatewayAgent.Validation;

public interface IConfigurationValidator
{
    ValidationResult Validate(GatewayConfiguration configuration);
}
