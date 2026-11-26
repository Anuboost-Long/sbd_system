/*
 * File: TurnstileVerifier.cs
 * Implements: Guide §2.5 server-side Cloudflare Turnstile check; any failure refuses the login.
 * Controls:   A8b
 */
using System.Text.Json;

namespace SBD.API.Services.Captcha;

public class TurnstileVerifier(HttpClient http, IConfiguration configuration, ILogger<TurnstileVerifier> logger) : ICaptchaVerifier
{
    private const string VerifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";

    // [Guide §2.5] Ask Cloudflare to verify the CAPTCHA token; if the call fails, times out or says no, the answer is "not verified".
    // Why: fail-safe default. An attacker who can block the check must not be able to skip it; lockout stays the main control because bots can solve CAPTCHAs (Searles et al., 2023).
    // Standard: OWASP ASVS 5.0 V6.3.1; Saltzer & Schroeder (1975), fail-safe defaults.
    // Evidence: test Captcha_VerifierDown_LoginRefused (A8b).
    public async Task<bool> VerifyAsync(string token, string? clientIp)
    {
        try
        {
            var form = new Dictionary<string, string>
            {
                ["secret"] = configuration["Turnstile:SecretKey"] ?? string.Empty,
                ["response"] = token,
            };
            if (clientIp is not null) form["remoteip"] = clientIp;

            using var response = await http.PostAsync(VerifyUrl, new FormUrlEncodedContent(form));
            if (!response.IsSuccessStatusCode) return false;

            using var body = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            return body.RootElement.TryGetProperty("success", out var success) && success.GetBoolean();
        }
        catch (Exception error)
        {
            logger.LogWarning(error, "CAPTCHA verification failed; login refused");
            return false;
        }
    }
}
