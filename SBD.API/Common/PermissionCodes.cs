namespace SBD.API.Common;

public static class PermissionCodes
{
    public const string CustomerSearch = "customer.search";
    public const string CustomerViewContact = "customer.view.contact";
    public const string CustomerViewCardMasked = "customer.view.card.masked";
    public const string CustomerCardReveal = "customer.card.reveal";
    public const string CustomerViewMedical = "customer.view.medical";
    public const string UserCreate = "user.create";
    public const string UserDisable = "user.disable";
    public const string UserRoleAssign = "user.role.assign";
    public const string UserPasswordReset = "user.password.reset";
    public const string UserMfaReset = "user.mfa.reset";
    public const string UserSearchUnlock = "user.search.unlock";

    public const string SessionPolicy = "session";
    public const string PermissionClaim = "perm";
    public const string DataConnectionClaim = "data_conn";
    public const string SessionIdClaim = "sid";
    public const string MustChangePasswordClaim = "must_change_password";

    public static readonly IReadOnlyList<string> All =
    [
        CustomerSearch, CustomerViewContact, CustomerViewCardMasked, CustomerCardReveal, CustomerViewMedical,
        UserCreate, UserDisable, UserRoleAssign, UserPasswordReset, UserMfaReset, UserSearchUnlock,
    ];
}
