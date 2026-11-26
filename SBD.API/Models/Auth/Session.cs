namespace SBD.API.Models.AuthDb;

public class Session
{
    public long SessionId { get; set; }

    public string UserId { get; set; } = string.Empty;
    public ApplicationUser User { get; set; } = null!;

    public byte[] TokenHash { get; set; } = [];
    public DateTime CreatedUtc { get; set; }
    public DateTime LastSeenUtc { get; set; }
    public DateTime AbsoluteExpiryUtc { get; set; }
    public DateTime? RevokedUtc { get; set; }
}
