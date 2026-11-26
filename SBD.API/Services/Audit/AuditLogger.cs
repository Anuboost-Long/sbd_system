/*
 * File: AuditLogger.cs
 * Implements: Guide §5 audit trail of logins, failures, role changes, card reveals and medical access.
 * Controls:   none (Guide §5 logging; risk R8)
 */
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Audit;

public class AuditLogger(AuthDbContext authDb, IHttpContextAccessor httpContextAccessor) : IAuditLogger
{
    // [Guide §5] One AuditLog row per event, taking only IDs, action, outcome and approval reference.
    // Why: no free-text field, so passwords, card numbers, medical status and search names cannot be logged.
    // Standard: OWASP ASVS 5.0 V16; OWASP Logging Cheat Sheet.
    // Evidence: test Login_WritesAuditRows (R8).
    public async Task LogAsync(
        AuditAction action,
        AuditOutcome outcome,
        string? actorUserId = null,
        string? targetUserId = null,
        int? targetCustomerId = null,
        string? approvalRef = null)
    {
        authDb.AuditLogs.Add(new AuditLog
        {
            OccurredUtc = DateTime.UtcNow,
            ActorUserId = actorUserId,
            Action = action,
            Outcome = outcome,
            TargetUserId = targetUserId,
            TargetCustomerId = targetCustomerId,
            ApprovalRef = approvalRef,
            ClientIp = httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString(),
        });
        await authDb.SaveChangesAsync();
    }

    public async Task LogCustomerAccessAsync(AuditAction action, string actorUserId, IEnumerable<int> customerIds)
    {
        var occurred = DateTime.UtcNow;
        var clientIp = httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString();

        authDb.AuditLogs.AddRange(customerIds.Select(customerId => new AuditLog
        {
            OccurredUtc = occurred,
            ActorUserId = actorUserId,
            Action = action,
            Outcome = AuditOutcome.Success,
            TargetCustomerId = customerId,
            ClientIp = clientIp,
        }));
        await authDb.SaveChangesAsync();
    }
}
