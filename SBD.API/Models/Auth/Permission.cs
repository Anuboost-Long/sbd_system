using System.ComponentModel.DataAnnotations;

namespace SBD.API.Models.AuthDb;

public class Permission
{
    public int PermissionId { get; set; }

    [Required, StringLength(50), RegularExpression(@"^[a-z.]+$")]
    public string Code { get; set; } = string.Empty;

    [Required, StringLength(200)]
    public string Description { get; set; } = string.Empty;
}
