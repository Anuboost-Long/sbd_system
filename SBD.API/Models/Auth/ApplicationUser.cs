using Microsoft.AspNetCore.Identity;

namespace SBD.API.Models.AuthDb;

public class ApplicationUser : IdentityUser
{
    public bool IsDisabled { get; set; }
    public DateTime? LastLoginUtc { get; set; }
    public DateTime? SearchPausedUntilUtc { get; set; }
    public DateTime CreatedUtc { get; set; }
}
