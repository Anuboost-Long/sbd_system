/*
 * File: SessionService.cs
 * Implements: Guide §2.4 session tokens: 256-bit random value, only its SHA-256 hash stored, 8-hour limit.
 * Controls:   A9
 */
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Session;

public class SessionService(AuthDbContext authDb, TimeProvider time) : ISessionService
{
    public static readonly TimeSpan AbsoluteLifetime = TimeSpan.FromHours(8);

    public static byte[] HashToken(byte[] token) => SHA256.HashData(token);

    // [Guide §2.4] Random 256-bit token, shown once; only its SHA-256 hash is stored, with an 8-hour expiry.
    // Why: a stolen AuthDb cannot be used to hijack sessions.
    // DEPLOYMENT ITEM, not active in this demo: production keeps the token in Next.js behind an HttpOnly, Secure, SameSite cookie; the demo returns a bearer token.
    // Standard: OWASP ASVS 5.0 V11.5.1; OWASP Session Management Cheat Sheet.
    // Evidence: test SessionToken_StoredAsHash (A9).
    public async Task<IssuedSession> CreateAsync(string userId)
    {
        var token = RandomNumberGenerator.GetBytes(32);
        var now = Now();

        authDb.Sessions.Add(new Models.AuthDb.Session
        {
            UserId = userId,
            TokenHash = HashToken(token),
            CreatedUtc = now,
            LastSeenUtc = now,
            AbsoluteExpiryUtc = now + AbsoluteLifetime,
        });
        await authDb.SaveChangesAsync();

        return new IssuedSession(WebEncoders.Base64UrlEncode(token), now + AbsoluteLifetime);
    }

    public async Task RevokeAsync(long sessionId) =>
        await authDb.Sessions
            .Where(s => s.SessionId == sessionId && s.RevokedUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedUtc, Now()));

    public async Task RevokeAllAsync(string userId) =>
        await authDb.Sessions
            .Where(s => s.UserId == userId && s.RevokedUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedUtc, Now()));

    public async Task RevokeOthersAsync(string userId, long keepSessionId) =>
        await authDb.Sessions
            .Where(s => s.UserId == userId && s.SessionId != keepSessionId && s.RevokedUtc == null)
            .ExecuteUpdateAsync(s => s.SetProperty(x => x.RevokedUtc, Now()));

    private DateTime Now()
    {
        var utc = time.GetUtcNow().UtcDateTime;
        return new DateTime(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
    }
}
