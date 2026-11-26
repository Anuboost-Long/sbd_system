/*
 * File: FieldEncryptionService.cs
 * Implements: Guide §3.3 AES-256-GCM encryption of medical status, card number and card expiry.
 * Controls:   E1, E2
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SBD.API.Services.Encryption;

public static class EncryptedColumns
{
    public const string MedicalStatus = "MedicalStatusEnc";
    public const string CardNumber = "CardNumberEnc";
    public const string CardExpiry = "CardExpiryEnc";
}

public class FieldEncryptionService
{
    private const string VersionPrefix = "v1:";
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private readonly byte[] key;

    public FieldEncryptionService(IOptions<FieldEncryptionOptions> options)
    {
        key = Convert.FromBase64String(options.Value.Key);
        if (key.Length != 32) throw new InvalidOperationException("FieldEncryption__Key must be 32 bytes, Base64 encoded.");
    }

    // [Guide §3.3] AES-256-GCM: random 12-byte nonce, 16-byte tag, customer ID + column as associated data; stored as v1: + Base64.
    // Why: DB staff and backups see only ciphertext; tampering or copying a value to another row fails.
    // DEPLOYMENT ITEM, not active in this demo: production keeps the key in a vault with rotation; the demo reads .env.
    // Standard: OWASP ASVS 5.0 V11.3.2, V11.3.3, V11.3.4; PCI DSS v4.0.1 Req 3.5.1.
    // Evidence: tests Encrypt_Decrypt_RoundTrip, SameValue_DifferentCiphertext (E1).
    public string Encrypt(string plaintext, int customerId, string column)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plainBytes, cipherBytes, tag, AssociatedData(customerId, column));

        return VersionPrefix + Convert.ToBase64String([.. nonce, .. cipherBytes, .. tag]);
    }

    // [Guide §3.3] Decrypt a stored value; an unknown version, a changed byte, or a value taken from another row or column is refused.
    // Why: GCM checks the tag before releasing any plaintext, so tampered or moved data fails instead of returning wrong data.
    // Standard: OWASP ASVS 5.0 V11.3.2, V11.3.3, V11.3.4.
    // Evidence: tests Tampered_Fails, CopiedToOtherRow_Fails, UnknownVersion_Rejected (E2).
    public string Decrypt(string stored, int customerId, string column)
    {
        if (!stored.StartsWith(VersionPrefix, StringComparison.Ordinal))
            throw new CryptographicException("Unknown encryption version.");

        var payload = Convert.FromBase64String(stored[VersionPrefix.Length..]);
        if (payload.Length < NonceSize + TagSize)
            throw new CryptographicException("Encrypted value is too short.");

        var nonce = payload[..NonceSize];
        var cipherBytes = payload[NonceSize..^TagSize];
        var tag = payload[^TagSize..];
        var plainBytes = new byte[cipherBytes.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(nonce, cipherBytes, tag, plainBytes, AssociatedData(customerId, column));

        return Encoding.UTF8.GetString(plainBytes);
    }

    private static byte[] AssociatedData(int customerId, string column) => Encoding.UTF8.GetBytes($"{customerId}:{column}");
}
