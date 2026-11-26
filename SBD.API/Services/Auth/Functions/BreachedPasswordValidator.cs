/*
 * File: BreachedPasswordValidator.cs
 * Implements: Guide §2.4 passwords on a public common-password list are refused.
 * Controls:   A4
 */
using Microsoft.AspNetCore.Identity;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Auth.Functions;

public class BreachedPasswordList
{
    private readonly HashSet<string> passwords;

    public BreachedPasswordList()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Resources", "breached-passwords.txt");
        passwords = new HashSet<string>(File.ReadLines(path), StringComparer.OrdinalIgnoreCase);
    }

    public bool Contains(string password) => passwords.Contains(password);
}

public class BreachedPasswordValidator(BreachedPasswordList list) : IPasswordValidator<ApplicationUser>
{
    // [Guide §2.4] Refuse any password found in the common-password list (10,000 entries from SecLists, case-insensitive).
    // Why: attackers try these first; length rules alone would still allow them for roles that need only 8 characters.
    // The file is read at startup, so a missing list stops the API instead of silently allowing weak passwords.
    // Standard: OWASP ASVS 5.0 V6.2.12.
    // Evidence: test BreachedPassword_Rejected (A4).
    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user, string? password) =>
        Task.FromResult(password is not null && list.Contains(password)
            ? IdentityResult.Failed(new IdentityError { Code = "PasswordBreached", Description = "That password is too common. Choose another." })
            : IdentityResult.Success);
}
