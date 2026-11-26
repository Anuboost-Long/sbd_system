/*
 * File: MfaTicketStore.cs
 * Implements: Guide §2.4 short-lived single-use ticket between the password step and the MFA step.
 * Controls:   A8
 */
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Caching.Memory;

namespace SBD.API.Services.Auth.Functions;

public enum MfaTicketKind
{
    Verify,
    Setup,
}

public record MfaTicket(string UserId, MfaTicketKind Kind);

public class MfaTicketStore(IMemoryCache cache)
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(5);

    // [Guide §2.4] After a correct password, issue a random 32-byte ticket valid for 5 minutes, tied to that user and used once.
    // Why: the MFA step must belong to the person who just passed the password step; the ticket cannot be reused or moved to another account.
    // Standard: OWASP ASVS 5.0 V6.3.3.
    // Evidence: tests Accounting_RequiresMfa, WrongMfaCode_CountsTowardLockout (A8).
    public string Issue(string userId, MfaTicketKind kind)
    {
        var ticket = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        cache.Set(Key(ticket), new MfaTicket(userId, kind), Lifetime);
        return ticket;
    }

    public MfaTicket? Peek(string? ticket, MfaTicketKind kind) =>
        !string.IsNullOrEmpty(ticket) && cache.TryGetValue(Key(ticket), out MfaTicket? entry) && entry!.Kind == kind
            ? entry
            : null;

    public void Consume(string ticket) => cache.Remove(Key(ticket));

    private static string Key(string ticket) =>
        "mfa:" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(ticket)));
}
