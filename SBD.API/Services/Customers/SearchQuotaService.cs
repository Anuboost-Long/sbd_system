/*
 * File: SearchQuotaService.cs
 * Implements: Guide §2.2, §6 daily search quotas, soft and hard limits, pause until unlock, search log and alphabet-walk alert.
 * Controls:   E3, E4, E5
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Customers.Functions;

namespace SBD.API.Services.Customers;

public class SearchQuotaService(AuthDbContext authDb, SearchFingerprint fingerprint, TimeProvider time)
{
    public const int DailySearches = 300;
    public const int DailyRecords = 2000;
    public const int AlphabetWalkSearches = 15;
    public static readonly TimeSpan AlphabetWalkWindow = TimeSpan.FromMinutes(10);

    // [Guide §2.2, §6] Before a search, count today's searches and records: alert at 50%, pause the user and refuse (429) at 100%.
    // Why: per-minute limits alone still allow bulk harvesting over a day (risk R4).
    // Standard: Guide §2.2, §6.
    // Evidence: tests DailyHardLimit_Pauses, SoftLimit_RaisesAlert, Unlock_ResumesSearch (E3).
    public async Task<bool> IsAllowedAsync(string userId)
    {
        var now = Now();
        var pausedUntil = await authDb.Users.Where(u => u.Id == userId).Select(u => u.SearchPausedUntilUtc).SingleAsync();
        if (pausedUntil > now) return false;

        var lastUnlock = await authDb.AuditLogs
            .Where(a => a.TargetUserId == userId && a.Action == AuditAction.SearchUnlocked && a.Outcome == AuditOutcome.Success)
            .MaxAsync(a => (DateTime?)a.OccurredUtc);
        var since = lastUnlock is { } unlocked && unlocked > now.Date ? unlocked : now.Date;

        var searches = await authDb.SearchLogs.CountAsync(s => s.UserId == userId && s.OccurredUtc >= since);
        var records = await authDb.SearchLogs.Where(s => s.UserId == userId && s.OccurredUtc >= since).SumAsync(s => (int?)s.ResultCount) ?? 0;

        if (searches >= DailySearches || records >= DailyRecords)
        {
            await authDb.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.SearchPausedUntilUtc, now.AddYears(100)));
            await RaiseAlertAsync(userId, SecurityAlertType.SearchHardLimit, since: null);
            return false;
        }

        if (searches >= DailySearches / 2 || records >= DailyRecords / 2)
            await RaiseAlertAsync(userId, SecurityAlertType.SearchSoftLimit, since);

        return true;
    }

    // [Guide §5, §6] Log each search without names (wildcard flag, prefix length, HMAC fingerprint, count); 15 different wildcard prefixes in 10 minutes raises an AlphabetWalk alert.
    // Why: detects a-z walking without keeping personal data. The 15 / 10 minutes threshold is a design choice.
    // Standard: OWASP ASVS 5.0 V16.
    // Evidence: tests SearchLog_ContainsNoNames, AlphabetWalk_RaisesAlert (E4, E5).
    public async Task RecordAsync(string userId, SearchCriteria criteria, int resultCount)
    {
        var prefixes = criteria.Prefixes.Select(t => t.Value).ToList();
        var prefixText = string.Join('|', prefixes);

        authDb.SearchLogs.Add(new SearchLog
        {
            UserId = userId,
            OccurredUtc = Now(),
            UsedWildcard = prefixes.Count > 0,
            PrefixLength = (byte)Math.Min(prefixText.Length, byte.MaxValue),
            PrefixFingerprint = prefixes.Count > 0 ? fingerprint.Compute(prefixText) : null,
            ResultCount = (short)resultCount,
        });
        await authDb.SaveChangesAsync();

        if (prefixes.Count == 0) return;

        var windowStart = Now() - AlphabetWalkWindow;
        var distinctPrefixes = await authDb.SearchLogs
            .Where(s => s.UserId == userId && s.UsedWildcard && s.OccurredUtc >= windowStart)
            .Select(s => s.PrefixFingerprint)
            .Distinct()
            .CountAsync();
        if (distinctPrefixes >= AlphabetWalkSearches)
            await RaiseAlertAsync(userId, SecurityAlertType.AlphabetWalk, windowStart);
    }

    private async Task RaiseAlertAsync(string userId, SecurityAlertType type, DateTime? since)
    {
        if (since is not null && await authDb.SecurityAlerts.AnyAsync(a => a.UserId == userId && a.AlertType == type && a.RaisedUtc >= since))
            return;

        authDb.SecurityAlerts.Add(new SecurityAlert { RaisedUtc = Now(), UserId = userId, AlertType = type });
        await authDb.SaveChangesAsync();
    }

    private DateTime Now()
    {
        var utc = time.GetUtcNow().UtcDateTime;
        return new DateTime(utc.Ticks - utc.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
    }
}
