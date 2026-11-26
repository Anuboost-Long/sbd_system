namespace SBD.API.Models.AuthDb;

public class AuditLog
{
    public long AuditId { get; set; }
    public DateTime OccurredUtc { get; set; }
    public string? ActorUserId { get; set; }
    public AuditAction Action { get; set; }
    public AuditOutcome Outcome { get; set; }
    public string? TargetUserId { get; set; }
    public int? TargetCustomerId { get; set; }
    public string? ApprovalRef { get; set; }
    public string? ClientIp { get; set; }
}
