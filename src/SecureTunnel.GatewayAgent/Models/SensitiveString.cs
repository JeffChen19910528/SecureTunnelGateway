namespace SecureTunnel.GatewayAgent.Models;

/// <summary>
/// Wraps a secret value (e.g. a WireGuard private key) so that accidental use in
/// string interpolation, logging, or ToString() never leaks the real content.
/// The real value is only obtainable via <see cref="Reveal"/>, which callers must
/// use deliberately and never pass to a logger.
/// </summary>
public sealed class SensitiveString
{
    private readonly string _value;

    public SensitiveString(string value)
    {
        _value = value;
    }

    public bool IsEmpty => string.IsNullOrEmpty(_value);

    /// <summary>Deliberate, explicit access to the real secret value. Never log the result.</summary>
    public string Reveal() => _value;

    public override string ToString() => "***REDACTED***";
}
