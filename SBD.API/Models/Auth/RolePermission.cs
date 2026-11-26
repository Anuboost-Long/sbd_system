using Microsoft.AspNetCore.Identity;

namespace SBD.API.Models.AuthDb;

public class RolePermission
{
    public string RoleId { get; set; } = string.Empty;
    public IdentityRole Role { get; set; } = null!;

    public int PermissionId { get; set; }
    public Permission Permission { get; set; } = null!;
}
