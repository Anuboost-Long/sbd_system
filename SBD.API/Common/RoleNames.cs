namespace SBD.API.Common;

public static class RoleNames
{
    public const string Normal = "Normal";
    public const string Accounting = "Accounting";
    public const string Privileged = "Privileged";
    public const string UserAdmin = "UserAdmin";

    public static readonly IReadOnlySet<string> RequiringMfa =
        new HashSet<string> { Accounting, Privileged, UserAdmin };
}
