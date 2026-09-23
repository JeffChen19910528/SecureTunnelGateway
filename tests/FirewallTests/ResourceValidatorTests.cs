using SecureTunnel.GatewayAgent.Firewall;
using SecureTunnel.GatewayAgent.Models;
using SecureTunnel.GatewayAgent.Validation;
using Xunit;

namespace SecureTunnel.GatewayAgent.FirewallTests;

public sealed class ResourceValidatorTests
{
    [Fact]
    public void Validate_ValidSingleAddress_IsValid()
    {
        var resource = MakeResource(destination: "10.20.0.10");
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.True(result.IsValid);
    }

    [Fact]
    public void Validate_ValidNarrowCidr_IsValid()
    {
        var resource = MakeResource(destination: "10.20.0.0/28");
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_EmptyDestination_Rejected(string destination)
    {
        var resource = MakeResource(destination: destination);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "destination");
    }

    [Theory]
    [InlineData("not-an-ip")]
    [InlineData("300.1.1.1")]
    [InlineData("10.20.0.0/33")]
    [InlineData("10.20.0.0/abc")]
    public void Validate_InvalidDestination_Rejected(string destination)
    {
        var resource = MakeResource(destination: destination);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "destination");
    }

    [Theory]
    [InlineData("0.0.0.0/0")]
    [InlineData("10.0.0.0/8")]
    [InlineData("0.0.0.0/1")]
    public void Validate_UnrestrictedDestination_Rejected(string destination)
    {
        var resource = MakeResource(destination: destination);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "destination" && e.Message.Contains("broad"));
    }

    [Fact]
    public void Validate_Ipv6Destination_Rejected()
    {
        var resource = MakeResource(destination: "2001:db8::1");
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "destination" && e.Message.Contains("IPv6"));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    public void Validate_InvalidPort_Rejected(int port)
    {
        var resource = MakeResource(port: port);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "port");
    }

    [Fact]
    public void Validate_PortEndBeforePortStart_Rejected()
    {
        var resource = MakeResource(port: 8080, portEnd: 8000);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "portEnd");
    }

    [Fact]
    public void Validate_InvalidPortEnd_Rejected()
    {
        var resource = MakeResource(port: 8000, portEnd: 70000);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "portEnd");
    }

    [Fact]
    public void Validate_ValidPortRange_IsValid()
    {
        var resource = MakeResource(port: 8000, portEnd: 8010);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_EmptyName_Rejected(string name)
    {
        var resource = MakeResource(name: name);
        var result = new ValidationResult();

        ResourceValidator.Validate(resource, result);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Field == "name");
    }

    private static ProtectedResource MakeResource(string name = "test", string destination = "10.20.0.10", int port = 443, int? portEnd = null) => new()
    {
        ResourceId = "resource-test",
        Name = name,
        Destination = destination,
        Protocol = Protocol.Tcp,
        Port = port,
        PortEnd = portEnd,
        Enabled = true,
        CreatedAtUtc = DateTimeOffset.UtcNow,
        UpdatedAtUtc = DateTimeOffset.UtcNow
    };
}
