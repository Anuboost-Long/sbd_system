/*
 * File: AdminService.cs
 * Implements: Guide §2.2, §2.6, §4.2, §4.4 User Admin actions: create, role change, disable, password reset, MFA reset, search unlock.
 * Controls:   R6
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Admin.Dtos;
using SBD.API.Services.Audit;
using SBD.API.Services.Session;

namespace SBD.API.Services.Admin;

public enum AdminOutcome { Ok, NotFound, SelfChange, Invalid }

public record AdminResult(AdminOutcome Outcome, IReadOnlyDictionary<string, string[]>? Errors = null, CreatedUserResponse? Created = null)
{
    public static readonly AdminResult Ok = new(AdminOutcome.Ok);
}

public class AdminService(
    UserManager<ApplicationUser> users,
    AuthDbContext authDb,
    ISessionService sessions,
    IAuditLogger audit,
    TimeProvider time)
{
    // [Guide §4.2, §4.4] Create a user with one role and a temporary password; the user must change it at first login.
    // Why: no half-created account, and every account has a manager approval reference.
    // Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V8.2.1.
    // Evidence: tests CreateUser_ForcesPasswordChange, CreateUser_UnknownRole_Rejected (R6).
    public async Task<AdminResult> CreateUserAsync(string actorId, string username, string role, string temporaryPassword, string approvalRef)
    {
        await using var transaction = await authDb.Database.BeginTransactionAsync();

        var user = new ApplicationUser { UserName = username };
        var steps = new List<Func<Task<IdentityResult>>>
        {
            () => users.CreateAsync(user, temporaryPassword),
            () => users.AddToRoleAsync(user, role),
            () => users.AddClaimAsync(user, new Claim(PermissionCodes.MustChangePasswordClaim, "true")),
        };
        foreach (var step in steps)
        {
            var result = await step();
            if (!result.Succeeded) return Invalid(result);
        }

        await audit.LogAsync(AuditAction.UserCreated, AuditOutcome.Success, actorId, user.Id, approvalRef: approvalRef);
        await RaiseRoleAlertAsync(user.Id, role);
        await transaction.CommitAsync();
        return new AdminResult(AdminOutcome.Ok, Created: new CreatedUserResponse(user.Id, username, role));
    }

    // [Guide §4.2, §4.4] Change the role, end the user's sessions, write the audit row and raise an alert, all in one transaction.
    // Why: if the audit row is refused (no approval reference), the role change is rolled back too.
    // Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V8.2.1, V8.3.1.
    // Evidence: tests RoleChange_RevokesSessions, RoleChange_DbRejectsMissingApproval_RollsBack (R6).
    public Task<AdminResult> AssignRoleAsync(string actorId, string targetId, string role, string? approvalRef) =>
        ActAsync(actorId, targetId, async user =>
        {
            var current = await users.GetRolesAsync(user);
            if (current.Count == 1 && current[0] == role)
                return new AdminResult(AdminOutcome.Invalid, new Dictionary<string, string[]> { ["role"] = ["The user already has this role."] });

            if (current.Count > 0)
            {
                var removed = await users.RemoveFromRolesAsync(user, current);
                if (!removed.Succeeded) return Invalid(removed);
            }
            var added = await users.AddToRoleAsync(user, role);
            if (!added.Succeeded) return Invalid(added);

            await sessions.RevokeAllAsync(user.Id);
            await audit.LogAsync(AuditAction.RoleAssigned, AuditOutcome.Success, actorId, user.Id, approvalRef: approvalRef);
            await RaiseRoleAlertAsync(user.Id, role);
            return AdminResult.Ok;
        });

    // [Guide §4.2] Disable the account on a manager's written request (approval reference) and end its sessions.
    // Why: access stops at once, not at session expiry.
    // Standard: ISO/IEC 27001:2022.
    // Evidence: tests DisabledUser_SessionRejected, Admin_Disable_RevokesSessions (E10, R6).
    public Task<AdminResult> DisableAsync(string actorId, string targetId, string approvalRef) =>
        ActAsync(actorId, targetId, async user =>
        {
            user.IsDisabled = true;
            var updated = await users.UpdateAsync(user);
            if (!updated.Succeeded) return Invalid(updated);

            await sessions.RevokeAllAsync(user.Id);
            await audit.LogAsync(AuditAction.UserDisabled, AuditOutcome.Success, actorId, user.Id, approvalRef: approvalRef);
            return AdminResult.Ok;
        });

    // [Guide §2.6] Reset a password: set a temporary one, force a change, end all sessions, log it.
    // Why: only a User Admin can reset, after an out-of-band identity check; no secret questions or email reset.
    // Standard: NIST SP 800-63B-4; ISO/IEC 27001:2022.
    // Evidence: test PasswordReset_ForcesChange_RevokesSessions (R6).
    public Task<AdminResult> ResetPasswordAsync(string actorId, string targetId, string temporaryPassword) =>
        ActAsync(actorId, targetId, async user =>
        {
            var token = await users.GeneratePasswordResetTokenAsync(user);
            var reset = await users.ResetPasswordAsync(user, token, temporaryPassword);
            if (!reset.Succeeded) return Invalid(reset);

            var claims = await users.GetClaimsAsync(user);
            if (!claims.Any(c => c.Type == PermissionCodes.MustChangePasswordClaim))
            {
                var flagged = await users.AddClaimAsync(user, new Claim(PermissionCodes.MustChangePasswordClaim, "true"));
                if (!flagged.Succeeded) return Invalid(flagged);
            }

            await sessions.RevokeAllAsync(user.Id);
            await audit.LogAsync(AuditAction.PasswordReset, AuditOutcome.Success, actorId, user.Id);
            return AdminResult.Ok;
        });

    // [Guide §2.6] Reset MFA: new authenticator key, MFA off until the user enrols again, end all sessions, log it.
    // Why: the old TOTP key must stop working.
    // Standard: OWASP ASVS 5.0 V6.3.3.
    // Evidence: test MfaReset_ForcesReEnrolment (R6).
    public Task<AdminResult> ResetMfaAsync(string actorId, string targetId) =>
        ActAsync(actorId, targetId, async user =>
        {
            var reset = await users.ResetAuthenticatorKeyAsync(user);
            if (!reset.Succeeded) return Invalid(reset);
            var disabled = await users.SetTwoFactorEnabledAsync(user, false);
            if (!disabled.Succeeded) return Invalid(disabled);

            await sessions.RevokeAllAsync(user.Id);
            await audit.LogAsync(AuditAction.MfaReset, AuditOutcome.Success, actorId, user.Id);
            return AdminResult.Ok;
        });

    // [Guide §2.2, §6] Unlock search: clear the pause, resolve the alert, write a SearchUnlocked audit row, in one transaction.
    // Why: a person decides whether the stopped search was legitimate, and the unlock is logged.
    // Standard: ISO/IEC 27001:2022.
    // Evidence: test SearchUnlock_ResumesSearch (E3, R6).
    public Task<AdminResult> UnlockSearchAsync(string actorId, string targetId) =>
        ActAsync(actorId, targetId, async user =>
        {
            user.SearchPausedUntilUtc = null;
            var updated = await users.UpdateAsync(user);
            if (!updated.Succeeded) return Invalid(updated);

            var now = time.GetUtcNow().UtcDateTime;
            await authDb.SecurityAlerts
                .Where(a => a.UserId == user.Id && a.AlertType == SecurityAlertType.SearchHardLimit && a.ResolvedUtc == null)
                .ExecuteUpdateAsync(a => a.SetProperty(x => x.ResolvedByUserId, actorId).SetProperty(x => x.ResolvedUtc, now));
            await audit.LogAsync(AuditAction.SearchUnlocked, AuditOutcome.Success, actorId, user.Id);
            return AdminResult.Ok;
        });

    // [Guide §4.4] An admin cannot change their own account; the attempt is refused and logged.
    // Why: separation of duties. The database CHECK CK_AuditLog_NoSelfAdmin is the second barrier.
    // Standard: ISO/IEC 27001:2022.
    // Evidence: test Admin_CannotChangeOwnRole (R6).
    private async Task<AdminResult> ActAsync(string actorId, string targetId, Func<ApplicationUser, Task<AdminResult>> action)
    {
        if (actorId == targetId)
        {
            await audit.LogAsync(AuditAction.AccessDenied, AuditOutcome.Denied, actorId, targetId);
            return new AdminResult(AdminOutcome.SelfChange);
        }

        await using var transaction = await authDb.Database.BeginTransactionAsync();
        var user = await users.FindByIdAsync(targetId);
        if (user is null) return new AdminResult(AdminOutcome.NotFound);

        var result = await action(user);
        if (result.Outcome == AdminOutcome.Ok) await transaction.CommitAsync();
        return result;
    }

    private async Task RaiseRoleAlertAsync(string userId, string role)
    {
        authDb.SecurityAlerts.Add(new SecurityAlert
        {
            RaisedUtc = time.GetUtcNow().UtcDateTime,
            UserId = userId,
            AlertType = RoleNames.RequiringMfa.Contains(role) ? SecurityAlertType.PrivilegedRoleAssigned : SecurityAlertType.RoleAssigned,
        });
        await authDb.SaveChangesAsync();
    }

    private static AdminResult Invalid(IdentityResult result) =>
        new(AdminOutcome.Invalid, result.Errors
            .GroupBy(e => e.Code)
            .ToDictionary(g => g.Key, g => g.Select(e => e.Description).ToArray()));
}
