/*
 * File: LoginFailureTracker.cs
 * Implements: Guide §2.5 failed-login count per username, which decides when the CAPTCHA is required.
 * Controls:   A8b
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;

namespace SBD.API.Services.Auth.Functions;

public class LoginFailureTracker(IMemoryCache cache)
{
    public const int FailuresBeforeCaptcha = 3;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    // [Guide §2.5] Count failed logins per username for 15 minutes, whether or not the username exists.
    // Why: if only real accounts triggered the CAPTCHA, an attacker could tell which usernames exist.
    // Standard: OWASP ASVS 5.0 V6.3.8.
    // Evidence: test Captcha_RequiredAfter3Failures (A8b).
    public int Count(string username) => cache.TryGetValue(Key(username), out int count) ? count : 0;

    public void Record(string username) => cache.Set(Key(username), Count(username) + 1, Window);

    public void Reset(string username) => cache.Remove(Key(username));

    private static string Key(string username) =>
        "loginfail:" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(username.ToLowerInvariant())));
}
