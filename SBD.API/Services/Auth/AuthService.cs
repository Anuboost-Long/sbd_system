/*
 * File: AuthService.cs
 * Implements: Guide §2.4, §2.5, §2.6 login, lockout, CAPTCHA, MFA, logout and the user's own password change.
 * Controls:   A5, A6, A8, A8b, R6
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SBD.API.Common;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Audit;
using SBD.API.Services.Auth.Dtos;
using SBD.API.Services.Auth.Functions;
using SBD.API.Services.Captcha;
using SBD.API.Services.Session;

namespace SBD.API.Services.Auth;

public class AuthService(
    UserManager<ApplicationUser> users,
    SignInManager<ApplicationUser> signIn,
    AuthDbContext authDb,
    IAuditLogger audit,
    ISessionService sessions,
    ICaptchaVerifier captcha,
    LoginFailureTracker failures,
    MfaTicketStore tickets,
    DummyPasswordHash dummyHash,
    IHttpContextAccessor httpContextAccessor,
    TimeProvider time)
{
    public async Task<AuthResult> LoginAsync(LoginRequest request)
    {
        var username = request.Username?.Trim() ?? string.Empty;
        var password = request.Password ?? string.Empty;

        // [Guide §2.5] From the 4th attempt on a username, a Turnstile token is required and checked on the server; if the check
        // fails or cannot run, the login is refused.
        // Why: fail-safe default. The count is kept per username text, so unknown names behave like real ones.
        // Standard: OWASP ASVS 5.0 V6.3.1; Saltzer & Schroeder (1975), fail-safe defaults.
        // Evidence: tests Captcha_RequiredAfter3Failures, Captcha_VerifierDown_LoginRefused (A8b).
        if (failures.Count(username) >= LoginFailureTracker.FailuresBeforeCaptcha
            && !await IsCaptchaVerifiedAsync(request.CaptchaToken))
            return AuthResult.Fail(AuthFailure.CaptchaRequired);

        var user = await users.FindByNameAsync(username);

        // [Guide §2.5] Unknown user, disabled account and locked account all take the same path as a wrong password:
        // one dummy hash check, then the same generic 401.
        // Why: the reply and its timing must not reveal whether a username exists or why a login failed.
        // Standard: OWASP ASVS 5.0 V6.3.8.
        // Evidence: test WrongUser_And_WrongPassword_SameResponse (A5).
        if (user is null || user.IsDisabled || await users.IsLockedOutAsync(user))
        {
            dummyHash.Verify(password);
            return await FailedLoginAsync(username, user?.Id);
        }

        // [Guide §2.5] Lock the account for 15 minutes after 5 failed logins (Identity lockout counts each wrong password).
        // Why: slows password guessing; lockout stays the main control because bots can solve CAPTCHAs.
        // Standard: OWASP ASVS 5.0 V6.3.1, V6.1.1; NIST SP 800-63B-4.
        // Evidence: test SixthAttempt_AccountLocked (A6).
        var check = await signIn.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (!check.Succeeded)
        {
            if (check.IsLockedOut) await RecordLockoutAsync(user.Id);
            return await FailedLoginAsync(username, user.Id);
        }

        failures.Reset(username);

        var roles = await users.GetRolesAsync(user);
        if (roles.Count != 1)
        {
            await audit.LogAsync(AuditAction.AccessDenied, AuditOutcome.Denied, user.Id);
            return AuthResult.Fail(AuthFailure.InvalidCredentials);
        }

        // [Guide §2.4] Accounting, Privileged and UserAdmin must also pass a TOTP code; a user who has not enrolled is sent to set up first.
        // Why: every account that can see card, medical or role data needs MFA; Normal users rely on the long password.
        // Standard: OWASP ASVS 5.0 V6.3.3.
        // Evidence: tests Accounting_RequiresMfa, Normal_NoMfaRequired (A8).
        if (RoleNames.RequiringMfa.Contains(roles[0]))
        {
            return user.TwoFactorEnabled
                ? AuthResult.Ok(new LoginResponse(MfaRequired: true, MfaTicket: tickets.Issue(user.Id, MfaTicketKind.Verify)))
                : AuthResult.Ok(new LoginResponse(MfaSetupRequired: true, MfaTicket: tickets.Issue(user.Id, MfaTicketKind.Setup)));
        }

        return AuthResult.Ok(await StartSessionAsync(user));
    }

    public async Task<MfaSetupResponse?> StartMfaSetupAsync(string? ticket)
    {
        var entry = tickets.Peek(ticket, MfaTicketKind.Setup);
        var user = entry is null ? null : await users.FindByIdAsync(entry.UserId);
        if (user is null || user.IsDisabled || await users.IsLockedOutAsync(user)) return null;

        var key = await users.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await users.ResetAuthenticatorKeyAsync(user);
            key = await users.GetAuthenticatorKeyAsync(user);
        }
        return new MfaSetupResponse(key!);
    }

    public Task<AuthResult> ConfirmMfaSetupAsync(MfaCodeRequest request) => CompleteMfaAsync(request, MfaTicketKind.Setup);

    public Task<AuthResult> VerifyMfaAsync(MfaCodeRequest request) => CompleteMfaAsync(request, MfaTicketKind.Verify);

    // [Guide §2.6] Change your own password: check the current one, apply the password rules, clear the must-change flag, end other sessions.
    // Why: the only way out of a forced change; a wrong current password counts toward lockout. No audit row: the schema has no PasswordChanged action.
    // Standard: NIST SP 800-63B-4; OWASP ASVS 5.0 V6.2.1, V6.2.12.
    // Evidence: tests PasswordReset_ForcesChange_RevokesSessions, ChangePassword_WrongCurrent_Rejected (R6).
    public async Task<string?> ChangePasswordAsync(string userId, long sessionId, ChangePasswordRequest request)
    {
        const string Rejected = "The password could not be changed. Check both passwords and try again.";
        var user = await users.FindByIdAsync(userId);
        if (user is null || string.IsNullOrEmpty(request.CurrentPassword) || string.IsNullOrEmpty(request.NewPassword))
            return Rejected;

        var result = await users.ChangePasswordAsync(user, request.CurrentPassword, request.NewPassword);
        if (!result.Succeeded)
        {
            if (result.Errors.Any(e => e.Code == nameof(IdentityErrorDescriber.PasswordMismatch)))
            {
                await users.AccessFailedAsync(user);
                if (await users.IsLockedOutAsync(user)) await RecordLockoutAsync(user.Id);
                return Rejected;
            }
            return string.Join(' ', result.Errors.Select(e => e.Description));
        }

        await users.ResetAccessFailedCountAsync(user);
        var pending = (await users.GetClaimsAsync(user)).Where(c => c.Type == PermissionCodes.MustChangePasswordClaim).ToList();
        if (pending.Count > 0) await users.RemoveClaimsAsync(user, pending);
        await sessions.RevokeOthersAsync(user.Id, sessionId);
        return null;
    }

    public async Task LogoutAsync(string userId, long sessionId)
    {
        await sessions.RevokeAsync(sessionId);
        await audit.LogAsync(AuditAction.Logout, AuditOutcome.Success, userId);
    }

    // [Guide §2.4] Check the TOTP code only if the account is not locked; a wrong code adds to the same failure counter as a wrong password.
    // Why: otherwise an attacker who knows the password could guess the 6-digit code without limit. LastLoginUtc is set only after MFA succeeds.
    // Standard: OWASP ASVS 5.0 V6.3.3, V6.3.1.
    // Evidence: test WrongMfaCode_CountsTowardLockout (A8).
    private async Task<AuthResult> CompleteMfaAsync(MfaCodeRequest request, MfaTicketKind kind)
    {
        var entry = tickets.Peek(request.MfaTicket, kind);
        var user = entry is null ? null : await users.FindByIdAsync(entry.UserId);
        if (user is null || user.IsDisabled)
            return AuthResult.Fail(AuthFailure.InvalidTicket);
        if (await users.IsLockedOutAsync(user))
            return AuthResult.Fail(AuthFailure.InvalidCode);

        var valid = await users.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, request.Code?.Replace(" ", "") ?? string.Empty);
        if (!valid)
        {
            await users.AccessFailedAsync(user);
            await audit.LogAsync(AuditAction.MfaFailed, AuditOutcome.Failure, user.Id);
            if (await users.IsLockedOutAsync(user)) await RecordLockoutAsync(user.Id);
            return AuthResult.Fail(AuthFailure.InvalidCode);
        }

        if (kind == MfaTicketKind.Setup) await users.SetTwoFactorEnabledAsync(user, true);
        tickets.Consume(request.MfaTicket!);
        await users.ResetAccessFailedCountAsync(user);
        return AuthResult.Ok(await StartSessionAsync(user));
    }

    private async Task<LoginResponse> StartSessionAsync(ApplicationUser user)
    {
        var session = await sessions.CreateAsync(user.Id);
        user.LastLoginUtc = time.GetUtcNow().UtcDateTime;
        await users.UpdateAsync(user);
        await audit.LogAsync(AuditAction.LoginSucceeded, AuditOutcome.Success, user.Id);
        return new LoginResponse(Token: session.Token, ExpiresUtc: session.ExpiresUtc);
    }

    private async Task<AuthResult> FailedLoginAsync(string username, string? userId)
    {
        failures.Record(username);
        await audit.LogAsync(AuditAction.LoginFailed, AuditOutcome.Failure, userId);
        return AuthResult.Fail(AuthFailure.InvalidCredentials);
    }

    private async Task RecordLockoutAsync(string userId)
    {
        await audit.LogAsync(AuditAction.AccountLocked, AuditOutcome.Denied, userId);
        authDb.SecurityAlerts.Add(new SecurityAlert
        {
            RaisedUtc = time.GetUtcNow().UtcDateTime,
            UserId = userId,
            AlertType = SecurityAlertType.AccountLocked,
        });
        await authDb.SaveChangesAsync();
    }

    private async Task<bool> IsCaptchaVerifiedAsync(string? token) =>
        !string.IsNullOrWhiteSpace(token)
        && await captcha.VerifyAsync(token, httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString());
}
