using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Audit;

public interface IAuditLogger
{
    Task LogAsync(
        AuditAction action,
        AuditOutcome outcome,
        string? actorUserId = null,
        string? targetUserId = null,
        int? targetCustomerId = null,
        string? approvalRef = null);

    Task LogCustomerAccessAsync(AuditAction action, string actorUserId, IEnumerable<int> customerIds);
}
