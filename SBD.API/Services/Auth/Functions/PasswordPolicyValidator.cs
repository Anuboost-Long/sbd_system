/*
 * File: PasswordPolicyValidator.cs
 * Implements: Guide §2.4 password rules (length 15, or 8 once MFA is enrolled; max 128; no composition rules).
 * Controls:   A3
 */
using Microsoft.AspNetCore.Identity;
using SBD.API.Common;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Auth.Functions;

public class PasswordPolicyValidator : IPasswordValidator<ApplicationUser>
{
    private const int MinLength = 15;
    private const int MinLengthWithMfa = 8;
    private const int MaxLength = 128;

    // [Guide §2.4] Length 15 (8 once MFA is enrolled), max 128, no composition rules.
    // Why: length beats complexity rules; an account without MFA has only the password.
    // Standard: OWASP ASVS 5.0 V6.2.1, V6.2.5, V6.2.9; NIST SP 800-63B-4.
    // Evidence: tests Password_14Chars_Rejected, Password_15Chars_Accepted, Password_NoCompositionRules (A3).
    public async Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password)
    {
        if (string.IsNullOrEmpty(password))
            return IdentityResult.Failed(new IdentityError { Code = "PasswordRequired", Description = "Enter a password." });

        var roles = await manager.GetRolesAsync(user);
        var minimum = user.TwoFactorEnabled && roles.Any(RoleNames.RequiringMfa.Contains) ? MinLengthWithMfa : MinLength;

        if (password.Length < minimum)
            return IdentityResult.Failed(new IdentityError { Code = "PasswordTooShort", Description = $"Use at least {minimum} characters." });
        if (password.Length > MaxLength)
            return IdentityResult.Failed(new IdentityError { Code = "PasswordTooLong", Description = $"Use at most {MaxLength} characters." });

        return IdentityResult.Success;
    }
}
