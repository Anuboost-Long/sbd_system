/*
 * File: IpAllowlistMiddleware.cs
 * Implements: Guide §2.3 only the Next.js server's address may call the API.
 * Controls:   E6
 */
using System.Net;
using Microsoft.Extensions.Options;
using SBD.API.SetUp;

namespace SBD.API.Middleware;

public class IpAllowlistMiddleware(RequestDelegate next, IOptions<SecurityOptions> options)
{
    private readonly IReadOnlySet<IPAddress> allowedIps = SecurityOptions.ParseIps(options.Value.AllowedIps);

    // [Guide §2.3] Accept a request only if its network address is on the allowlist; otherwise reply 403.
    // Why: small attack surface. The address comes from the connection itself, never from Host or X-Forwarded-For headers,
    // which a caller can fake. An address proves origin, not identity, so the API key is also required.
    // Standard: ASD ISM-1139; Saltzer & Schroeder (1975).
    // Evidence: test NotAllowlistedIp_403 (E6).
    public Task Invoke(HttpContext context)
    {
        var remote = context.Connection.RemoteIpAddress?.MapToIPv6();
        if (remote is null || !allowedIps.Contains(remote))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }

        return next(context);
    }
}
