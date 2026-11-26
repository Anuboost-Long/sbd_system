/*
 * File: RateLimitSetup.cs
 * Implements: Guide §2.5, §2.2 request rate limits for login and search.
 * Controls:   A7, E3
 */
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

namespace SBD.API.SetUp;

public static class RateLimitSetup
{
    public const string LoginPolicy = "login";
    public const string SearchPolicy = "search";

    public static IServiceCollection AddSecurityRateLimiter(this IServiceCollection services) =>
        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

            // [Guide §2.5] At most 10 login attempts per minute from one network address; the 11th gets 429.
            // Why: slows password guessing from one source; lockout stays the main control.
            // Standard: OWASP ASVS 5.0 V6.3.1.
            // Evidence: test LoginRateLimit_11thRequest_429 (A7).
            options.AddPolicy(LoginPolicy, context => FixedPerMinute(
                context.Connection.RemoteIpAddress?.ToString() ?? "unknown", permitLimit: 10));

            // [Guide §2.2] At most 30 searches per minute per signed-in user; the 31st gets 429.
            // Why: per-minute caps slow data harvesting (risk R4); daily quotas add the longer limit.
            // Standard: Guide §2.2 and risk R4.
            // Evidence: test SearchRateLimit_31st_429 (E3).
            options.AddPolicy(SearchPolicy, context => FixedPerMinute(
                context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous", permitLimit: 30));
        });

    private static RateLimitPartition<string> FixedPerMinute(string partitionKey, int permitLimit) =>
        RateLimitPartition.GetFixedWindowLimiter(partitionKey, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        });
}
