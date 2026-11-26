/*
 * File: InactiveAccountService.cs
 * Implements: Guide §4.2 accounts with no login for 90 days are disabled automatically.
 * Controls:   E10
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Audit;
using SBD.API.Services.Session;

namespace SBD.API.Services.Admin;

public class InactiveAccountService(AuthDbContext authDb, ISessionService sessions, IAuditLogger audit, TimeProvider time)
{
    public static readonly TimeSpan InactiveAfter = TimeSpan.FromDays(90);

    // [Guide §4.2] Disable accounts with no login for 90 days (or never logged in and 90 days old), end their sessions, log it.
    // Why: unused accounts are an unwatched attack surface.
    // Standard: ISO/IEC 27001:2022.
    // Evidence: test InactiveAccount_Disabled (E10).
    public async Task<int> DisableInactiveAsync()
    {
        var cutoff = time.GetUtcNow().UtcDateTime - InactiveAfter;
        var inactiveIds = await authDb.Users
            .Where(u => !u.IsDisabled && (u.LastLoginUtc ?? u.CreatedUtc) < cutoff)
            .Select(u => u.Id)
            .ToListAsync();

        foreach (var id in inactiveIds)
        {
            await using var transaction = await authDb.Database.BeginTransactionAsync();
            await authDb.Users.Where(u => u.Id == id).ExecuteUpdateAsync(u => u.SetProperty(x => x.IsDisabled, true));
            await sessions.RevokeAllAsync(id);
            await audit.LogAsync(AuditAction.UserDisabled, AuditOutcome.Success, actorUserId: null, targetUserId: id);
            await transaction.CommitAsync();
        }
        return inactiveIds.Count;
    }
}
