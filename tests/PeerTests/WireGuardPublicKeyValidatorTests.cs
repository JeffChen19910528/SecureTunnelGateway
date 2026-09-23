using SecureTunnel.GatewayAgent.Peers;
using Xunit;

namespace SecureTunnel.GatewayAgent.PeerTests;

public sealed class WireGuardPublicKeyValidatorTests
{
    [Fact]
    public void TryValidate_RealisticKey_Succeeds()
    {
        // A real WireGuard public key: 32 random bytes, base64-encoded.
        var bytes = new byte[32];
        new Random(42).NextBytes(bytes);
        var key = Convert.ToBase64String(bytes);

        var ok = WireGuardPublicKeyValidator.TryValidate(key, out var error);

        Assert.True(ok);
        Assert.Null(error);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryValidate_Empty_Fails(string? key)
    {
        var ok = WireGuardPublicKeyValidator.TryValidate(key, out var error);

        Assert.False(ok);
        Assert.Contains("empty", error);
    }

    [Fact]
    public void TryValidate_NotBase64_Fails()
    {
        var ok = WireGuardPublicKeyValidator.TryValidate("not-valid-base64!!!***", out var error);

        Assert.False(ok);
        Assert.Contains("Base64", error);
    }

    [Theory]
    [InlineData("QQ==")] // decodes to 1 byte
    [InlineData("QUJDRA==")] // decodes to 4 bytes
    public void TryValidate_WrongDecodedLength_Fails(string key)
    {
        var ok = WireGuardPublicKeyValidator.TryValidate(key, out var error);

        Assert.False(ok);
        Assert.Contains("32 bytes", error);
    }

    [Theory]
    [InlineData((byte)0x00)] // all-zero bytes - matches the "AAAA...=" style placeholders used in Phase 1 docs
    [InlineData((byte)0xFF)]
    [InlineData((byte)0x41)] // all-'A' ASCII bytes, another common placeholder pattern
    public void TryValidate_PlaceholderLookingKey_Fails(byte repeatedByte)
    {
        var key = Convert.ToBase64String(Enumerable.Repeat(repeatedByte, 32).ToArray());

        var ok = WireGuardPublicKeyValidator.TryValidate(key, out var error);

        Assert.False(ok);
        Assert.Contains("placeholder", error);
    }

    [Fact]
    public void TryValidate_TrimsWhitespace()
    {
        var bytes = new byte[32];
        new Random(7).NextBytes(bytes);
        var key = "  " + Convert.ToBase64String(bytes) + "  ";

        var ok = WireGuardPublicKeyValidator.TryValidate(key, out var error);

        Assert.True(ok);
        Assert.Null(error);
    }
}
