/*
 * File: SearchFingerprint.cs
 * Implements: Guide §5, §6 keyed fingerprint of a search prefix, so patterns can be detected without keeping names.
 * Controls:   E5
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SBD.API.Services.Encryption;

namespace SBD.API.Services.Customers.Functions;

public class SearchFingerprint(IOptions<SearchFingerprintOptions> options)
{
    private readonly byte[] key = Convert.FromBase64String(options.Value.Key);

    // [Guide §5, §6] Store an HMAC-SHA-256 of the lower-case search prefix, using a key held only by the API, instead of the prefix itself.
    // Why: the system can still count distinct prefixes (alphabet-walking) without keeping personal data (Privacy Act 1988).
    // Standard: OWASP ASVS 5.0 V16; OWASP Logging Cheat Sheet.
    // Evidence: test SearchLog_ContainsNoNames (E5).
    public byte[] Compute(string prefix) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(prefix.ToLowerInvariant()));
}
