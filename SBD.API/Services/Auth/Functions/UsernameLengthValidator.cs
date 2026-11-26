/*
 * File: UsernameLengthValidator.cs
 * Implements: Guide §2.4 usernames are 3 to 32 characters.
 * Controls:   none (Guide §2.4 username rule; the database CHECK CK_AspNetUsers_UserName repeats it)
 */
using Microsoft.AspNetCore.Identity;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Auth.Functions;

public class UsernameLengthValidator : IUserValidator<ApplicationUser>
{
    // [Guide §2.4] Usernames are 3 to 32 characters (letters, digits, '.' and '_' are enforced by the Identity option).
    // Why: matches the database CHECK, so a bad name is refused with a clear message instead of a database error.
    // Standard: Guide §2.4.
    // Evidence: database CHECK CK_AspNetUsers_UserName; no separate test or control ID.
    public Task<IdentityResult> ValidateAsync(UserManager<ApplicationUser> manager, ApplicationUser user) =>
        Task.FromResult(user.UserName is { Length: >= 3 and <= 32 }
            ? IdentityResult.Success
            : IdentityResult.Failed(new IdentityError { Code = "UsernameLength", Description = "Use 3 to 32 characters for the username." }));
}
