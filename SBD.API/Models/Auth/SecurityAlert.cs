namespace SBD.API.Models.AuthDb;

public class SecurityAlert
{
    public long AlertId { get; set; }
    public DateTime RaisedUtc { get; set; }
    public string UserId { get; set; } = string.Empty;
    public SecurityAlertType AlertType { get; set; }
    public string? ResolvedByUserId { get; set; }
    public DateTime? ResolvedUtc { get; set; }
}
