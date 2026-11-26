/*
 * File: SecurityHeadersMiddleware.cs
 * Implements: Guide §2.3, §2.2 response security headers on every reply.
 * Controls:   E8
 */
namespace SBD.API.Middleware;

public class SecurityHeadersMiddleware(RequestDelegate next)
{
    // [Guide §2.3, §2.2] Add no-sniff, no-framing, no-referrer, no-store and a deny-all content policy to every response.
    // Why: the API only returns JSON, so browsers are told to run, frame, cache and leak nothing from it.
    // Standard: OWASP HTTP Headers Cheat Sheet; OWASP ASVS 5.0 V16.
    // Evidence: test SecurityHeaders_Present (E8).
    public Task Invoke(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            headers["X-Content-Type-Options"] = "nosniff";
            headers["X-Frame-Options"] = "DENY";
            headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'";
            headers["Referrer-Policy"] = "no-referrer";
            headers["Cache-Control"] = "no-store";
            return Task.CompletedTask;
        });

        return next(context);
    }
}
