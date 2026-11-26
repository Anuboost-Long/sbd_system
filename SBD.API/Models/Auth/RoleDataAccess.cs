using Microsoft.AspNetCore.Identity;

namespace SBD.API.Models.AuthDb;

public class RoleDataAccess
{
    public string RoleId { get; set; } = string.Empty;
    public IdentityRole Role { get; set; } = null!;

    public string? DataViewName { get; set; }
    public string? ConnectionName { get; set; }
}
