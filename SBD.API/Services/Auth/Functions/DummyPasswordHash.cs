/*
 * File: DummyPasswordHash.cs
 * Implements: Guide §2.5 similar response time whether or not the account exists.
 * Controls:   A5
 */
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Auth.Functions;

public class DummyPasswordHash
{
    private readonly PasswordHasher<ApplicationUser> hasher;
    private readonly ApplicationUser dummyUser = new();
    private readonly string dummyHash;

    public DummyPasswordHash(IOptions<PasswordHasherOptions> options)
    {
        hasher = new PasswordHasher<ApplicationUser>(options);
        dummyHash = hasher.HashPassword(dummyUser, Guid.NewGuid().ToString("N"));
    }

    // [Guide §2.5] When the user is unknown, disabled or locked, still run one full password-hash check against a fixed dummy hash.
    // Why: the slow hash is most of a login's run time, so skipping it would let an attacker time which usernames are real.
    // Standard: OWASP ASVS 5.0 V6.3.8.
    // Evidence: test WrongUser_And_WrongPassword_SameResponse (A5).
    public void Verify(string password) => hasher.VerifyHashedPassword(dummyUser, dummyHash, password);
}
