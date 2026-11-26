/*
 * File: ApiKeyMiddleware.cs
 * Implements: Guide §2.3 only the Next.js server, which holds the API key, may call the API.
 * Controls:   E6
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using SBD.API.SetUp;

namespace SBD.API.Middleware;

public class ApiKeyMiddleware(RequestDelegate next, IOptions<SecurityOptions> options)
{
    private readonly byte[] expectedKeyHash = SHA256.HashData(Encoding.UTF8.GetBytes(options.Value.ApiKey));

    // [Guide §2.3] Require the X-Api-Key header and compare it in constant time; a missing or wrong key gets 401.
    // Why: proves the caller is our own server. Both values are hashed first so the comparison time reveals nothing
    // about the key or its length.
    // Standard: OWASP ASVS 5.0 V8.2.1; Saltzer & Schroeder (1975).
    // Evidence: tests MissingApiKey_401, WrongApiKey_401 (E6).
    public Task Invoke(HttpContext context)
    {
        var provided = context.Request.Headers["X-Api-Key"].ToString();
        var providedHash = SHA256.HashData(Encoding.UTF8.GetBytes(provided));

        if (provided.Length == 0 || !CryptographicOperations.FixedTimeEquals(providedHash, expectedKeyHash))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return Task.CompletedTask;
        }

        return next(context);
    }
}
