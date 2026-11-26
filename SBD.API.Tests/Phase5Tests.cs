using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Admin;
using SBD.API.Services.Auth.Dtos;
using SBD.API.Services.Session;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase5Tests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private const string AdminNetworkIp = "127.0.0.1";
    private const string ApprovalRef = "CHG-1042";

    private static HttpClient WithToken(HttpClient client, HttpClient from)
    {
        client.DefaultRequestHeaders.Authorization = from.DefaultRequestHeaders.Authorization;
        return client;
    }

    // A signed-in UserAdmin, calling from the internal (admin) address.
    private async Task<(HttpClient Client, string AdminId)> AdminAsync()
    {
        var (signedIn, adminId, _) = await factory.SignInAsync(RoleNames.UserAdmin);
        return (WithToken(factory.CreateApiClient(remoteIp: AdminNetworkIp), signedIn), adminId);
    }

    private async Task<(HttpClient Client, string UserId, string UserName)> SignedInAsync(string role)
    {
        var (client, userId, userName) = await factory.SignInAsync(role);
        return (client, userId, userName);
    }

    private static Task<HttpResponseMessage> PostAsync(HttpClient client, string url, object? body = null) =>
        client.PostAsJsonAsync(url, body ?? new { });

    private Task<string?> RoleOfAsync(string userId) =>
        factory.WithDbAsync(async (db, users) => (await users.GetRolesAsync((await users.FindByIdAsync(userId))!)).SingleOrDefault());

    private Task<int> AuditCountAsync(AuditAction action, AuditOutcome outcome, string? actorId = null, string? targetId = null) =>
        factory.WithDbAsync((db, _) => db.AuditLogs.CountAsync(a =>
            a.Action == action && a.Outcome == outcome
            && (actorId == null || a.ActorUserId == actorId) && (targetId == null || a.TargetUserId == targetId)));

    private static HttpClient CloneWithToken(AuthApiFactory f, HttpClient signedIn) =>
        WithToken(f.CreateApiClient(remoteIp: AuthApiFactory.NextIp()), signedIn);

    // R6 – Guide §4.4 Normal, Accounting and Privileged users cannot call any admin route
    [Theory]
    [InlineData(RoleNames.Normal)]
    [InlineData(RoleNames.Accounting)]
    [InlineData(RoleNames.Privileged)]
    public async Task NonAdmin_CannotCallAdmin(string role)
    {
        var (signedIn, _, _) = await SignedInAsync(role);
        var client = WithToken(factory.CreateApiClient(remoteIp: AdminNetworkIp), signedIn);

        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/admin/users", new { username = "x", role = "Normal", temporaryPassword = "y", approvalRef = ApprovalRef })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/admin/users/abc/role", new { role = "Normal", approvalRef = ApprovalRef })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/admin/users/abc/search-unlock")).StatusCode);
    }

    // R6 – Guide §4.4 a User Admin has no customer permission, so search and card reveal are refused
    [Fact]
    public async Task Admin_CannotSearch()
    {
        var (client, _) = await AdminAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/customers/search", new { lastName = "Smith" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/customers/1/card/reveal")).StatusCode);
    }

    // R6 – Guide §4.4 the same admin session is refused from an address outside the internal list, and the refusal is audited
    [Fact]
    public async Task Admin_FromExternalIp_403()
    {
        var (internalClient, adminId) = await AdminAsync();
        var (_, targetId, _) = await SignedInAsync(RoleNames.Normal);
        var external = CloneWithToken(factory, internalClient);
        var before = await AuditCountAsync(AuditAction.AccessDenied, AuditOutcome.Denied, adminId);

        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(external, $"/admin/users/{targetId}/disable", new { approvalRef = ApprovalRef })).StatusCode);

        Assert.Equal(before + 1, await AuditCountAsync(AuditAction.AccessDenied, AuditOutcome.Denied, adminId));
        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(internalClient, $"/admin/users/{targetId}/disable", new { approvalRef = ApprovalRef })).StatusCode);
    }

    // R6 – Guide §4.2 disabling needs the manager's approval reference
    [Fact]
    public async Task Disable_NeedsApprovalRef()
    {
        var (client, _) = await AdminAsync();
        var (_, targetId, _) = await SignedInAsync(RoleNames.Normal);

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, $"/admin/users/{targetId}/disable")).StatusCode);

        Assert.False(await factory.WithDbAsync((db, _) => db.Users.Where(u => u.Id == targetId).Select(u => u.IsDisabled).SingleAsync()));
    }

    // R6 – Guide §4.4 a UserAdmin account without MFA enrolled is refused on the internal network too, and the refusal is audited
    [Fact]
    public async Task Admin_WithoutMfa_403()
    {
        var (adminId, _) = await factory.CreateUserAsync(RoleNames.UserAdmin);
        var (_, targetId, _) = await SignedInAsync(RoleNames.Normal);
        var session = await factory.WithServiceAsync<ISessionService, IssuedSession>(s => s.CreateAsync(adminId));
        var client = factory.CreateApiClient(remoteIp: AdminNetworkIp);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", session.Token);

        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{targetId}/disable", new { approvalRef = ApprovalRef })).StatusCode);

        Assert.Equal(1, await AuditCountAsync(AuditAction.AccessDenied, AuditOutcome.Denied, adminId));
        Assert.False(await factory.WithDbAsync((db, _) => db.Users.Where(u => u.Id == targetId).Select(u => u.IsDisabled).SingleAsync()));
    }

    // R6 – Guide §4.4 an admin cannot change their own role, disable, reset password or MFA, or unlock search
    [Fact]
    public async Task Admin_CannotChangeOwnRole()
    {
        var (client, adminId) = await AdminAsync();

        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{adminId}/role", new { role = "Privileged", approvalRef = ApprovalRef })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{adminId}/disable", new { approvalRef = ApprovalRef })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{adminId}/password-reset", new { temporaryPassword = "a-long-temporary-password" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{adminId}/mfa-reset")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, $"/admin/users/{adminId}/search-unlock")).StatusCode);

        Assert.Equal(RoleNames.UserAdmin, await RoleOfAsync(adminId));
        Assert.Equal(0, await AuditCountAsync(AuditAction.RoleAssigned, AuditOutcome.Success, adminId));
        Assert.True(await AuditCountAsync(AuditAction.AccessDenied, AuditOutcome.Denied, adminId, adminId) >= 5);
    }

    // R6 – Guide §4.4 a new account has one role, must change its temporary password, and is audited with the approval reference
    [Fact]
    public async Task CreateUser_ForcesPasswordChange()
    {
        var (client, adminId) = await AdminAsync();
        var username = "n" + Guid.NewGuid().ToString("N")[..12];
        var temporary = "temporary-" + AuthApiFactory.UniqueLetters(10);

        var response = await PostAsync(client, "/admin/users", new { username, role = "Accounting", temporaryPassword = temporary, approvalRef = ApprovalRef });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = (await response.Content.ReadFromJsonAsync<SBD.API.Services.Admin.Dtos.CreatedUserResponse>())!;
        factory.TrackUser(created.UserId);

        Assert.Equal(RoleNames.Accounting, await RoleOfAsync(created.UserId));
        var row = await factory.WithDbAsync((db, _) => db.AuditLogs.SingleAsync(a => a.Action == AuditAction.UserCreated && a.TargetUserId == created.UserId));
        Assert.Equal(ApprovalRef, row.ApprovalRef);
        Assert.Equal(adminId, row.ActorUserId);
        Assert.Equal(1, await factory.WithDbAsync((db, _) => db.SecurityAlerts.CountAsync(a => a.UserId == created.UserId && a.AlertType == SecurityAlertType.PrivilegedRoleAssigned)));

        var login = await factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp()).PostAsJsonAsync("/auth/login", new LoginRequest(username, temporary, null));
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        Assert.True((await login.Content.ReadFromJsonAsync<LoginResponse>())!.MfaSetupRequired);
    }

    // R6 – Guide §4.1 an unknown role, a missing approval reference or a weak temporary password is refused and creates nothing
    [Theory]
    [InlineData("Manager", "CHG-1", "a-long-temporary-password")]
    [InlineData("Normal", "", "a-long-temporary-password")]
    [InlineData("Normal", "CHG-1", "short")]
    public async Task CreateUser_UnknownRole_Rejected(string role, string approvalRef, string password)
    {
        var (client, _) = await AdminAsync();
        var username = "n" + Guid.NewGuid().ToString("N")[..12];

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, "/admin/users", new { username, role, temporaryPassword = password, approvalRef })).StatusCode);

        Assert.False(await factory.WithDbAsync((db, _) => db.Users.AnyAsync(u => u.UserName == username)));
    }

    // R6 – Guide §4.4 a role change without an approval reference is refused by the API and the role stays the same
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("bad ref;")]
    public async Task RoleChange_NeedsApprovalRef(string? approvalRef)
    {
        var (client, _) = await AdminAsync();
        var (_, targetId, _) = await SignedInAsync(RoleNames.Normal);

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, $"/admin/users/{targetId}/role", new { role = "Accounting", approvalRef })).StatusCode);

        Assert.Equal(RoleNames.Normal, await RoleOfAsync(targetId));
    }

    // R6 – Guide §4.4 if the audit row is refused by the database CHECK, the role change is rolled back with it
    [Fact]
    public async Task RoleChange_DbRejectsMissingApproval_RollsBack()
    {
        var (adminId, _) = await factory.CreateUserAsync(RoleNames.UserAdmin);
        var (targetClient, targetId, _) = await SignedInAsync(RoleNames.Normal);

        await Assert.ThrowsAsync<DbUpdateException>(() =>
            factory.WithServiceAsync<AdminService, AdminResult>(s => s.AssignRoleAsync(adminId, targetId, RoleNames.Accounting, approvalRef: null)));

        Assert.Equal(RoleNames.Normal, await RoleOfAsync(targetId));
        Assert.Equal(0, await factory.WithDbAsync((db, _) => db.SecurityAlerts.CountAsync(a => a.UserId == targetId)));
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(targetClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
    }

    // R6 – Guide §4.2, §4.4 a role change takes effect on the next request, ends old sessions, and writes the audit row and alert
    [Fact]
    public async Task RoleChange_RevokesSessions()
    {
        var (admin, adminId) = await AdminAsync();
        var (targetClient, targetId, _) = await SignedInAsync(RoleNames.Normal);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(targetClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);

        var response = await PostAsync(admin, $"/admin/users/{targetId}/role", new { role = "Accounting", approvalRef = ApprovalRef });

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(targetClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
        Assert.Equal(RoleNames.Accounting, await RoleOfAsync(targetId));
        var row = await factory.WithDbAsync((db, _) => db.AuditLogs.SingleAsync(a => a.Action == AuditAction.RoleAssigned && a.TargetUserId == targetId));
        Assert.Equal((adminId, ApprovalRef), (row.ActorUserId, row.ApprovalRef));
        Assert.Equal(1, await factory.WithDbAsync((db, _) => db.SecurityAlerts.CountAsync(a => a.UserId == targetId && a.AlertType == SecurityAlertType.PrivilegedRoleAssigned)));
    }

    // R6 – Guide §4.2 a role change to Normal raises the ordinary RoleAssigned alert
    [Fact]
    public async Task RoleChange_ToNormal_RaisesPlainAlert()
    {
        var (admin, _) = await AdminAsync();
        var (_, targetId, _) = await SignedInAsync(RoleNames.Accounting);

        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(admin, $"/admin/users/{targetId}/role", new { role = "Normal", approvalRef = ApprovalRef })).StatusCode);

        Assert.Equal(1, await factory.WithDbAsync((db, _) => db.SecurityAlerts.CountAsync(a => a.UserId == targetId && a.AlertType == SecurityAlertType.RoleAssigned)));
    }

    // E10 – Guide §4.2 disabling an account ends its session at once and blocks new logins
    [Fact]
    public async Task Admin_Disable_RevokesSessions()
    {
        var (admin, adminId) = await AdminAsync();
        var (targetClient, targetId, userName) = await SignedInAsync(RoleNames.Normal);

        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(admin, $"/admin/users/{targetId}/disable", new { approvalRef = ApprovalRef })).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(targetClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp())
            .PostAsJsonAsync("/auth/login", new LoginRequest(userName, AuthApiFactory.Password, null))).StatusCode);
        Assert.Equal(1, await AuditCountAsync(AuditAction.UserDisabled, AuditOutcome.Success, adminId, targetId));
    }

    // R6 – Guide §2.6 a reset ends every session, forces a password change, and the user can do nothing else until they change it
    [Fact]
    public async Task PasswordReset_ForcesChange_RevokesSessions()
    {
        var (admin, adminId) = await AdminAsync();
        var (oldClient, targetId, userName) = await SignedInAsync(RoleNames.Normal);
        var temporary = "temporary-" + AuthApiFactory.UniqueLetters(10);
        var search = new { lastName = "Zzzzqx" };

        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(admin, $"/admin/users/{targetId}/password-reset", new { temporaryPassword = temporary })).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(oldClient, "/customers/search", search)).StatusCode);
        var login = await factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp()).PostAsJsonAsync("/auth/login", new LoginRequest(userName, temporary, null));
        var client = factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp());
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await login.Content.ReadFromJsonAsync<LoginResponse>())!.Token);
        Assert.Equal(HttpStatusCode.Forbidden, (await PostAsync(client, "/customers/search", search)).StatusCode);

        var otherLogin = await factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp()).PostAsJsonAsync("/auth/login", new LoginRequest(userName, temporary, null));
        var otherClient = factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp());
        otherClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", (await otherLogin.Content.ReadFromJsonAsync<LoginResponse>())!.Token);

        var newPassword = "brand-new-" + AuthApiFactory.UniqueLetters(10);
        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(client, "/auth/change-password", new { currentPassword = temporary, newPassword })).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(client, "/customers/search", search)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(otherClient, "/customers/search", search)).StatusCode);
        Assert.Equal(1, await AuditCountAsync(AuditAction.PasswordReset, AuditOutcome.Success, adminId, targetId));
    }

    // R6 – Guide §2.6 change-password refuses a wrong current password, a short new password and a breached one
    [Fact]
    public async Task ChangePassword_WrongCurrent_Rejected()
    {
        var (client, userId, _) = await SignedInAsync(RoleNames.Normal);

        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, "/auth/change-password", new { currentPassword = "not-the-password-at-all", newPassword = "brand-new-" + AuthApiFactory.UniqueLetters(10) })).StatusCode);
        Assert.Equal(1, await factory.WithDbAsync((db, _) => db.Users.Where(u => u.Id == userId).Select(u => u.AccessFailedCount).SingleAsync()));
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, "/auth/change-password", new { currentPassword = AuthApiFactory.Password, newPassword = "short" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await PostAsync(client, "/auth/change-password", new { currentPassword = AuthApiFactory.Password, newPassword = "films+pic+galeries" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(client, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
    }

    // R6 – Guide §2.6 an MFA reset ends sessions and the next login must enrol a new authenticator
    [Fact]
    public async Task MfaReset_ForcesReEnrolment()
    {
        var (admin, adminId) = await AdminAsync();
        var (oldClient, targetId, userName) = await SignedInAsync(RoleNames.Accounting);
        var oldKey = await factory.WithDbAsync(async (_, users) => (await users.GetAuthenticatorKeyAsync((await users.FindByIdAsync(targetId))!))!);

        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(admin, $"/admin/users/{targetId}/mfa-reset")).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await PostAsync(oldClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
        var state = await factory.WithDbAsync(async (_, users) =>
        {
            var user = (await users.FindByIdAsync(targetId))!;
            return (user.TwoFactorEnabled, key: await users.GetAuthenticatorKeyAsync(user));
        });
        Assert.False(state.TwoFactorEnabled);
        Assert.NotEqual(oldKey, state.key);
        var login = await factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp()).PostAsJsonAsync("/auth/login", new LoginRequest(userName, AuthApiFactory.Password, null));
        Assert.True((await login.Content.ReadFromJsonAsync<LoginResponse>())!.MfaSetupRequired);
        Assert.Equal(1, await AuditCountAsync(AuditAction.MfaReset, AuditOutcome.Success, adminId, targetId));
    }

    // E3 – Guide §2.2, §6 the unlock endpoint clears the pause, resolves the alert and restarts the daily count
    [Fact]
    public async Task SearchUnlock_ResumesSearch()
    {
        var (admin, adminId) = await AdminAsync();
        var (client, targetId, _) = await SignedInAsync(RoleNames.Normal);
        await factory.WithDbAsync(async (db, _) =>
        {
            db.SearchLogs.AddRange(Enumerable.Range(0, 300).Select(_ => new SearchLog { UserId = targetId, OccurredUtc = DateTime.UtcNow, ResultCount = 0 }));
            await db.SaveChangesAsync();
            return 0;
        });
        var search = new { lastName = "Zzzzqx" };
        Assert.Equal(HttpStatusCode.TooManyRequests, (await PostAsync(client, "/customers/search", search)).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await PostAsync(admin, $"/admin/users/{targetId}/search-unlock")).StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await PostAsync(client, "/customers/search", search)).StatusCode);
        var alert = await factory.WithDbAsync((db, _) => db.SecurityAlerts.SingleAsync(a => a.UserId == targetId && a.AlertType == SecurityAlertType.SearchHardLimit));
        Assert.Equal(adminId, alert.ResolvedByUserId);
        Assert.NotNull(alert.ResolvedUtc);
        Assert.Equal(1, await AuditCountAsync(AuditAction.SearchUnlocked, AuditOutcome.Success, adminId, targetId));
    }

    // R6 – Guide §4.4 an unknown target gives 404
    [Fact]
    public async Task Admin_UnknownUser_404()
    {
        var (admin, _) = await AdminAsync();

        Assert.Equal(HttpStatusCode.NotFound, (await PostAsync(admin, "/admin/users/no-such-user/mfa-reset")).StatusCode);
    }

    // E10 – Guide §4.2 an account with no login for over 90 days (or never logged in and created over 90 days ago) is disabled; a recent one is not
    [Fact]
    public async Task InactiveAccount_Disabled()
    {
        var (staleId, _) = await factory.CreateUserAsync(RoleNames.Normal);
        var (neverLoggedInId, _) = await factory.CreateUserAsync(RoleNames.Normal);
        var (recentId, _) = await factory.CreateUserAsync(RoleNames.Normal);
        var (activeClient, activeId, _) = await SignedInAsync(RoleNames.Normal);
        await factory.WithDbAsync(async (db, _) =>
        {
            var now = DateTime.UtcNow;
            await db.Users.Where(u => u.Id == staleId).ExecuteUpdateAsync(u => u.SetProperty(x => x.LastLoginUtc, now.AddDays(-91)));
            await db.Users.Where(u => u.Id == neverLoggedInId).ExecuteUpdateAsync(u => u.SetProperty(x => x.CreatedUtc, now.AddDays(-91)));
            await db.Users.Where(u => u.Id == recentId).ExecuteUpdateAsync(u => u.SetProperty(x => x.LastLoginUtc, now.AddDays(-89)));
            return 0;
        });

        var disabled = await factory.WithServiceAsync<InactiveAccountService, int>(s => s.DisableInactiveAsync());

        Assert.True(disabled >= 2);
        var flags = await factory.WithDbAsync((db, _) => db.Users
            .Where(u => new[] { staleId, neverLoggedInId, recentId, activeId }.Contains(u.Id))
            .ToDictionaryAsync(u => u.Id, u => u.IsDisabled));
        Assert.True(flags[staleId]);
        Assert.True(flags[neverLoggedInId]);
        Assert.False(flags[recentId]);
        Assert.False(flags[activeId]);
        var audit = await factory.WithDbAsync((db, _) => db.AuditLogs.SingleAsync(a => a.Action == AuditAction.UserDisabled && a.TargetUserId == staleId));
        Assert.Null(audit.ActorUserId);
        Assert.Equal(HttpStatusCode.OK, (await PostAsync(activeClient, "/customers/search", new { lastName = "Zzzzqx" })).StatusCode);
    }
}
