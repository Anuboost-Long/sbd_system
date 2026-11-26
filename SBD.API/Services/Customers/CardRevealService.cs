/*
 * File: CardRevealService.cs
 * Implements: Guide §3.3, §4.4 card reveal checked on the server, logged, and limited to 20 per user per day.
 * Controls:   R5
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Models.CustomerDb.Views;
using SBD.API.Services.Audit;
using SBD.API.Services.Customers.Dtos;
using SBD.API.Services.Encryption;

namespace SBD.API.Services.Customers;

public enum RevealStatus
{
    Ok,
    NotFound,
    LimitReached,
    Forbidden,
}

public record RevealOutcome(RevealStatus Status, RevealResponse? Card = null);

public class CardRevealService(
    CustomerAccess access, FieldEncryptionService encryption, AuthDbContext authDb, IAuditLogger audit, TimeProvider time)
{
    public const int DailyLimit = 20;

    // [Guide §3.3, §4.4] Decrypt the card only after a server permission check; log CardRevealed (customer ID, never the number); max 20 per user per day.
    // Why: the full card number is the most damaging field, so every disclosure is traceable and bulk reveal is blocked.
    // Standard: OWASP ASVS 5.0 V8.2.1; PCI DSS v4.0.1 Req 3.4.1.
    // Evidence: tests Reveal_Normal_Forbidden, Reveal_Accounting_Logged, Reveal_21st_Blocked (R5).
    public async Task<RevealOutcome> RevealAsync(string userId, string? connectionName, int customerId)
    {
        var today = time.GetUtcNow().UtcDateTime.Date;
        var revealsToday = await authDb.AuditLogs.CountAsync(a =>
            a.ActorUserId == userId && a.Action == AuditAction.CardRevealed && a.Outcome == AuditOutcome.Success && a.OccurredUtc >= today);
        if (revealsToday >= DailyLimit)
        {
            if (!await authDb.SecurityAlerts.AnyAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.CardRevealLimit && a.RaisedUtc >= today))
            {
                authDb.SecurityAlerts.Add(new SecurityAlert { RaisedUtc = time.GetUtcNow().UtcDateTime, UserId = userId, AlertType = SecurityAlertType.CardRevealLimit });
                await authDb.SaveChangesAsync();
            }
            await audit.LogAsync(AuditAction.AccessDenied, AuditOutcome.Denied, userId, targetCustomerId: customerId);
            return new RevealOutcome(RevealStatus.LimitReached);
        }

        var card = connectionName switch
        {
            CustomerAccess.AccountingConnection => await FindCardAsync(access.Accounting.Customers, customerId),
            CustomerAccess.PrivilegedConnection => await FindCardAsync(access.Privileged.Customers, customerId),
            _ => null,
        };
        if (connectionName is not (CustomerAccess.AccountingConnection or CustomerAccess.PrivilegedConnection))
            return new RevealOutcome(RevealStatus.Forbidden);
        if (card is null) return new RevealOutcome(RevealStatus.NotFound);

        await audit.LogAsync(AuditAction.CardRevealed, AuditOutcome.Success, userId, targetCustomerId: customerId);
        return new RevealOutcome(RevealStatus.Ok, new RevealResponse(
            CardNumber.Unpad(encryption.Decrypt(card.CardNumberEnc, customerId, EncryptedColumns.CardNumber)),
            encryption.Decrypt(card.CardExpiryEnc, customerId, EncryptedColumns.CardExpiry)));
    }

    // [Guide §3.2] parameterised
    private static Task<CardFields?> FindCardAsync<TRow>(IQueryable<TRow> rows, int customerId) where TRow : class, ICardRow =>
        rows.AsNoTracking().Where(r => r.CustomerId == customerId)
            .Select(r => new CardFields(r.CardNumberEnc, r.CardExpiryEnc)).SingleOrDefaultAsync();

    private record CardFields(string CardNumberEnc, string CardExpiryEnc);
}
