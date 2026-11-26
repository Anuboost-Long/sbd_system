using System.Buffers.Binary;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Models.AuthDb;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase3PasswordTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private async Task<IdentityResult> ValidateAsync(string role, string password, bool mfaEnrolled = false)
    {
        var (userId, _) = await factory.CreateUserAsync(role);
        return await factory.WithDbAsync(async (db, users) =>
        {
            var user = (await users.FindByIdAsync(userId))!;
            if (mfaEnrolled) user.TwoFactorEnabled = true;
            var errors = new List<IdentityError>();
            foreach (var validator in users.PasswordValidators)
                errors.AddRange((await validator.ValidateAsync(users, user, password)).Errors);
            return errors.Count == 0 ? IdentityResult.Success : IdentityResult.Failed([.. errors]);
        });
    }

    // A3 – Guide §2.4 minimum length 15 for a role without MFA
    [Fact]
    public async Task Password_14Chars_Rejected() =>
        Assert.Contains("PasswordTooShort", (await ValidateAsync(RoleNames.Normal, "abcdefghijklmn")).Errors.Select(e => e.Code));

    // A3 – Guide §2.4 exactly 15 characters accepted
    [Fact]
    public async Task Password_15Chars_Accepted() =>
        Assert.True((await ValidateAsync(RoleNames.Normal, "qwertyuiopasdfg")).Succeeded);

    // A3 – Guide §2.4 at least 64 characters accepted
    [Fact]
    public async Task Password_64Chars_Accepted() =>
        Assert.True((await ValidateAsync(RoleNames.Normal, string.Concat(Enumerable.Repeat("blue-river-stone-", 4))[..64])).Succeeded);

    // A3 – Guide §2.4 no composition rules: all lowercase letters, no digit or symbol, is accepted
    [Fact]
    public async Task Password_NoCompositionRules() =>
        Assert.True((await ValidateAsync(RoleNames.Normal, "onlylowercaseletters")).Succeeded);

    // A3 – Guide §2.4 once MFA is enrolled, 8 characters are enough; 7 are not
    [Fact]
    public async Task Password_8Chars_AcceptedWhenMfaEnrolled_7Rejected()
    {
        Assert.True((await ValidateAsync(RoleNames.Accounting, "xk-vq-pt", mfaEnrolled: true)).Succeeded);
        Assert.False((await ValidateAsync(RoleNames.Accounting, "xk-vq-p", mfaEnrolled: true)).Succeeded);
    }

    // A3 – Guide §2.4 an MFA role that has not enrolled yet still needs 15 characters
    [Fact]
    public async Task Password_8Chars_RejectedForMfaRoleNotYetEnrolled() =>
        Assert.Contains("PasswordTooShort", (await ValidateAsync(RoleNames.Privileged, "xk-vq-pt")).Errors.Select(e => e.Code));

    // A4 – Guide §2.4 breached password refused ("password" is 8 characters, so only the list can reject it for an MFA role)
    [Fact]
    public async Task BreachedPassword_Rejected() =>
        Assert.Contains("PasswordBreached", (await ValidateAsync(RoleNames.Accounting, "password")).Errors.Select(e => e.Code));

    // A1 – Guide §2.4 the stored password is a hash, not the text
    [Fact]
    public async Task Password_IsStoredAsHash_NotPlainText()
    {
        var (userId, _) = await factory.CreateUserAsync(RoleNames.Normal);

        var stored = await factory.WithDbAsync((db, _) =>
            db.Users.Where(u => u.Id == userId).Select(u => u.PasswordHash).SingleAsync());

        Assert.NotNull(stored);
        Assert.DoesNotContain(AuthApiFactory.Password, stored);
        Assert.StartsWith("AQAAAA", stored);
    }

    // A2 – Guide §2.4 PBKDF2-HMAC-SHA512 with 600,000 iterations (Identity v3 layout: marker, PRF, iterations, salt length, salt, subkey)
    [Fact]
    public async Task Hasher_Uses600kIterations()
    {
        var (userId, _) = await factory.CreateUserAsync(RoleNames.Normal);
        var stored = await factory.WithDbAsync((db, _) =>
            db.Users.Where(u => u.Id == userId).Select(u => u.PasswordHash).SingleAsync());

        var bytes = Convert.FromBase64String(stored!);

        Assert.Equal(0x01, bytes[0]);
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(1, 4)));
        Assert.Equal(600_000u, BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(5, 4)));
    }

    // R3 – Guide §4.1 every permission code in the code exists in the database, and the database has no others
    [Fact]
    public async Task PermissionConstants_MatchDatabase()
    {
        var codes = await factory.WithDbAsync((db, _) => db.Permissions.Select(p => p.Code).ToListAsync());

        Assert.Equal(PermissionCodes.All.Order(), codes.Order());
    }

    // A1 – Guide §2.4 the Identity model matches the AuthDb schema: create, assign a role, load it all back
    [Fact]
    public async Task IdentitySchema_MatchesDatabase()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.UserAdmin);

        var loaded = await factory.WithDbAsync(async (db, users) =>
        {
            var user = await users.FindByNameAsync(userName);
            return (user, roles: await users.GetRolesAsync(user!));
        });

        Assert.Equal(userId, loaded.user!.Id);
        Assert.Equal([RoleNames.UserAdmin], loaded.roles);
        Assert.False(loaded.user.IsDisabled);
        Assert.True(loaded.user.CreatedUtc > DateTime.UtcNow.AddMinutes(-5));
    }
}
