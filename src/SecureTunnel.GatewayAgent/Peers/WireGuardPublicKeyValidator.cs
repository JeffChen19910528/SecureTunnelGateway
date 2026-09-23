namespace SecureTunnel.GatewayAgent.Peers;

/// <summary>
/// Validates the *shape* of a WireGuard public key (base64, 32 decoded bytes, not an
/// obvious placeholder). This is a format check only - it cannot and does not verify
/// the key is a real Curve25519 point or that the caller actually controls the matching
/// private key (WireGuard's own handshake is what proves that at connection time).
/// Deliberately does not depend on `wg` being installed, so it works identically on
/// Windows dev machines and WSL2 - see tests/PeerTests.
/// </summary>
public static class WireGuardPublicKeyValidator
{
    public static bool TryValidate(string? publicKey, out string? error)
    {
        if (string.IsNullOrWhiteSpace(publicKey))
        {
            error = "Public key must not be empty.";
            return false;
        }

        var trimmed = publicKey.Trim();

        byte[] decoded;
        try
        {
            decoded = Convert.FromBase64String(trimmed);
        }
        catch (FormatException)
        {
            error = "Public key is not valid Base64.";
            return false;
        }

        if (decoded.Length != 32)
        {
            error = $"Public key decodes to {decoded.Length} bytes; a WireGuard public key must decode to exactly 32 bytes.";
            return false;
        }

        // Reject obvious placeholders: every decoded byte identical (all-zero, all-0xFF,
        // and base64 strings made of a single repeated character such as the
        // "AAAAAAAA...=" examples used in Phase 1 documentation all decode this way).
        if (decoded.Distinct().Count() == 1)
        {
            error = "Public key looks like a placeholder (all decoded bytes are identical), not a real WireGuard key.";
            return false;
        }

        error = null;
        return true;
    }
}
