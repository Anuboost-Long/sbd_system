namespace SBD.API.Models.AuthDb;

public enum AuditAction
{
    LoginSucceeded,
    LoginFailed,
    AccountLocked,
    MfaFailed,
    Logout,
    CardRevealed,
    MedicalViewed,
    AccessDenied,
    UserCreated,
    UserDisabled,
    RoleAssigned,
    PasswordReset,
    MfaReset,
    SearchUnlocked,
}

public enum AuditOutcome
{
    Success,
    Denied,
    Failure,
}

public enum SecurityAlertType
{
    SearchSoftLimit,
    SearchHardLimit,
    AlphabetWalk,
    CardRevealLimit,
    AccountLocked,
    RoleAssigned,
    PrivilegedRoleAssigned,
}
