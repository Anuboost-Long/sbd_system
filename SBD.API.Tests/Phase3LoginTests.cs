using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Auth.Dtos;
using SBD.API.Services.Captcha;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase3LoginTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private static readonly DateTime Now = DateTime.UtcNow;

    private static Task<HttpResponseMessage> LoginAsync(HttpClient client, string username, string password, string? captcha = null) =>
        client.PostAsJsonAsync("/auth/login", new LoginRequest(username, password, captcha));

    private HttpClient NewClient() => factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp());

    private static HttpClient WithToken(HttpClient client, string token)
    {
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private async Task<string> SignInAsync(string role)
    {
        var (_, userName) = await factory.CreateUserAsync(role);
        var response = await LoginAsync(NewClient(), userName, AuthApiFactory.Password);
        return (await response.Content.ReadFromJsonAsync<LoginResponse>())!.Token!;
    }

    private async Task EnrolMfaAsync(string userId) =>
        await factory.WithDbAsync(async (db, users) =>
        {
            var user = (await users.FindByIdAsync(userId))!;
            await users.ResetAuthenticatorKeyAsync(user);
            await users.SetTwoFactorEnabledAsync(user, true);
            return 0;
        });

    private Task<string> AuthenticatorKeyAsync(string userId) =>
        factory.WithDbAsync(async (db, users) => (await users.GetAuthenticatorKeyAsync((await users.FindByIdAsync(userId))!))!);

    // A8 – Guide §2.4 Normal users sign in with the password only
    [Fact]
    public async Task Normal_NoMfaRequired()
    {
        var (_, userName) = await factory.CreateUserAsync(RoleNames.Normal);

        var body = await (await LoginAsync(NewClient(), userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>();

        Assert.False(body!.MfaRequired);
        Assert.False(body.MfaSetupRequired);
        Assert.False(string.IsNullOrEmpty(body.Token));
    }

    // A8 – Guide §2.4 Accounting must enrol and then pass a TOTP code on every login
    [Fact]
    public async Task Accounting_RequiresMfa()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Accounting);
        var client = NewClient();

        var first = (await (await LoginAsync(client, userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.True(first.MfaSetupRequired);
        Assert.Null(first.Token);

        var key = (await (await client.PostAsJsonAsync("/auth/mfa/setup", new MfaTicketRequest(first.MfaTicket)))
            .Content.ReadFromJsonAsync<MfaSetupResponse>())!.ManualKey;
        var confirmed = (await (await client.PostAsJsonAsync("/auth/mfa/confirm", new MfaCodeRequest(first.MfaTicket, Totp.Code(key))))
            .Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.False(string.IsNullOrEmpty(confirmed.Token));

        var second = (await (await LoginAsync(client, userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.True(second.MfaRequired);
        Assert.Null(second.Token);

        var verified = (await (await client.PostAsJsonAsync("/auth/mfa", new MfaCodeRequest(second.MfaTicket, Totp.Code(key))))
            .Content.ReadFromJsonAsync<LoginResponse>())!;
        Assert.False(string.IsNullOrEmpty(verified.Token));

        var replay = await client.PostAsJsonAsync("/auth/mfa", new MfaCodeRequest(second.MfaTicket, Totp.Code(key)));
        Assert.Equal(HttpStatusCode.Unauthorized, replay.StatusCode);
    }

    // A8 – Guide §2.4 a wrong TOTP code counts toward the lockout
    [Fact]
    public async Task WrongMfaCode_CountsTowardLockout()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Privileged);
        await EnrolMfaAsync(userId);
        var key = await AuthenticatorKeyAsync(userId);
        var client = NewClient();
        var ticket = (await (await LoginAsync(client, userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!.MfaTicket;
        var wrong = Totp.Code(key) == "000000" ? "111111" : "000000";

        for (var attempt = 1; attempt <= 5; attempt++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.PostAsJsonAsync("/auth/mfa", new MfaCodeRequest(ticket, wrong))).StatusCode);

        var lockedUntil = await factory.WithDbAsync((db, _) => db.Users.Where(u => u.Id == userId).Select(u => u.LockoutEnd).SingleAsync());
        Assert.True(lockedUntil > DateTimeOffset.UtcNow);

        var correctCodeWhileLocked = await client.PostAsJsonAsync("/auth/mfa", new MfaCodeRequest(ticket, Totp.Code(key)));
        Assert.Equal(HttpStatusCode.Unauthorized, correctCodeWhileLocked.StatusCode);

        var failures = await factory.WithDbAsync((db, _) =>
            db.AuditLogs.CountAsync(a => a.ActorUserId == userId && a.Action == AuditAction.MfaFailed));
        Assert.Equal(5, failures);
    }

    // A6 – Guide §2.5 five wrong passwords lock the account; the 6th attempt fails even with the right password
    [Fact]
    public async Task SixthAttempt_AccountLocked()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = NewClient();

        for (var attempt = 1; attempt <= 5; attempt++)
            Assert.Equal(HttpStatusCode.Unauthorized, (await LoginAsync(client, userName, "wrong-password-" + attempt, captcha: "ok")).StatusCode);

        var sixth = await LoginAsync(client, userName, AuthApiFactory.Password, captcha: "ok");

        Assert.Equal(HttpStatusCode.Unauthorized, sixth.StatusCode);
        var lockedUntil = await factory.WithDbAsync((db, _) => db.Users.Where(u => u.Id == userId).Select(u => u.LockoutEnd).SingleAsync());
        Assert.True(lockedUntil > DateTimeOffset.UtcNow.AddMinutes(14));

        var audits = await factory.WithDbAsync(async (db, _) => (
            locked: await db.AuditLogs.CountAsync(a => a.ActorUserId == userId && a.Action == AuditAction.AccountLocked),
            alert: await db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.AccountLocked)));
        Assert.Equal(1, audits.locked);
        Assert.Equal(1, audits.alert);
    }

    // A5 – Guide §2.5 unknown user, wrong password, disabled and locked accounts all get the same reply
    [Fact]
    public async Task WrongUser_And_WrongPassword_SameResponse()
    {
        var (_, existing) = await factory.CreateUserAsync(RoleNames.Normal);
        var (disabledId, disabled) = await factory.CreateUserAsync(RoleNames.Normal);
        await factory.WithDbAsync(async (db, _) => await db.Users.Where(u => u.Id == disabledId).ExecuteUpdateAsync(u => u.SetProperty(x => x.IsDisabled, true)));

        var (lockedId, locked) = await factory.CreateUserAsync(RoleNames.Normal);
        await factory.WithDbAsync(async (db, users) =>
        {
            await users.SetLockoutEndDateAsync((await users.FindByIdAsync(lockedId))!, DateTimeOffset.UtcNow.AddMinutes(15));
            return 0;
        });

        var replies = new List<(HttpStatusCode Status, string Body)>();
        foreach (var (name, password) in new[] { ("nobody" + Guid.NewGuid().ToString("N")[..8], "whatever-password-1"), (existing, "wrong-password-xyz"), (disabled, AuthApiFactory.Password), (locked, AuthApiFactory.Password) })
        {
            var response = await LoginAsync(NewClient(), name, password);
            replies.Add((response.StatusCode, await response.Content.ReadAsStringAsync()));
        }

        Assert.All(replies, reply => Assert.Equal(HttpStatusCode.Unauthorized, reply.Status));
        Assert.Single(replies.Select(reply => reply.Body).Distinct());
        Assert.Contains("Invalid username or password.", replies[0].Body);
    }

    // A8b – Guide §2.5 CAPTCHA required from the 4th attempt on a username
    [Fact]
    public async Task Captcha_RequiredAfter3Failures()
    {
        var (_, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = NewClient();
        factory.Captcha.Result = true;
        var callsBefore = factory.Captcha.Calls;

        for (var attempt = 1; attempt <= 3; attempt++)
            Assert.DoesNotContain("captchaRequired\":true", await (await LoginAsync(client, userName, "wrong-password-" + attempt)).Content.ReadAsStringAsync());

        var fourthWithoutToken = await LoginAsync(client, userName, AuthApiFactory.Password);
        Assert.Equal(HttpStatusCode.Unauthorized, fourthWithoutToken.StatusCode);
        Assert.Contains("captchaRequired\":true", await fourthWithoutToken.Content.ReadAsStringAsync());
        Assert.Equal(callsBefore, factory.Captcha.Calls);

        var withToken = await LoginAsync(client, userName, AuthApiFactory.Password, captcha: "token");
        Assert.Equal(HttpStatusCode.OK, withToken.StatusCode);
        Assert.Equal(callsBefore + 1, factory.Captcha.Calls);
    }

    // A8b – Guide §2.5 the same count applies to an unknown username, so the CAPTCHA does not reveal which names exist
    [Fact]
    public async Task Captcha_AlsoRequiredForUnknownUser()
    {
        var client = NewClient();
        var name = "ghost" + Guid.NewGuid().ToString("N")[..8];

        for (var attempt = 1; attempt <= 3; attempt++) await LoginAsync(client, name, "wrong-password-" + attempt);

        Assert.Contains("captchaRequired\":true", await (await LoginAsync(client, name, "wrong-password-4")).Content.ReadAsStringAsync());
    }

    // A8b – Guide §2.5 if the CAPTCHA cannot be verified the login is refused, even with the right password
    [Fact]
    public async Task Captcha_VerifierDown_LoginRefused()
    {
        var (_, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = NewClient();
        for (var attempt = 1; attempt <= 3; attempt++) await LoginAsync(client, userName, "wrong-password-" + attempt);
        factory.Captcha.Result = false;

        var response = await LoginAsync(client, userName, AuthApiFactory.Password, captcha: "token");
        factory.Captcha.Result = true;

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // A8b – Guide §2.5 the real Turnstile client treats a network failure as "not verified"
    [Fact]
    public async Task TurnstileVerifier_NetworkFailure_ReturnsFalse()
    {
        var verifier = new TurnstileVerifier(
            new HttpClient(new ThrowingHandler()), new Microsoft.Extensions.Configuration.ConfigurationBuilder().Build(),
            Microsoft.Extensions.Logging.Abstractions.NullLogger<TurnstileVerifier>.Instance);

        Assert.False(await verifier.VerifyAsync("token", "127.0.0.1"));
    }

    // A9 – Guide §2.4 only the SHA-256 hash of the 256-bit token is stored
    [Fact]
    public async Task SessionToken_StoredAsHash()
    {
        var token = await SignInAsync(RoleNames.Normal);
        var raw = WebEncoders.Base64UrlDecode(token);

        var (hashRows, rawRows) = await factory.WithDbAsync(async (db, _) => (
            await db.Sessions.CountAsync(s => s.TokenHash == SHA256.HashData(raw)),
            await db.Sessions.CountAsync(s => s.TokenHash == raw)));

        Assert.Equal(32, raw.Length);
        Assert.Equal(1, hashRows);
        Assert.Equal(0, rawRows);
    }

    // R2 – Guide §4.4 a role sent by the client in a header, the query or the body is ignored
    [Fact]
    public async Task ForgedRole_Ignored()
    {
        var client = WithToken(NewClient(), await SignInAsync(RoleNames.Normal));
        client.DefaultRequestHeaders.Add("Role", RoleNames.Privileged);
        client.DefaultRequestHeaders.Add("X-Role", RoleNames.Privileged);

        var viaQuery = await (await client.GetAsync("/test/whoami?role=Privileged")).Content.ReadFromJsonAsync<WhoAmI>();
        var viaBody = await (await client.PostAsJsonAsync("/test/whoami", new { role = "Privileged" })).Content.ReadFromJsonAsync<WhoAmI>();

        Assert.Equal(RoleNames.Normal, viaQuery!.Role);
        Assert.Equal(RoleNames.Normal, viaBody!.Role);
        Assert.DoesNotContain(PermissionCodes.CustomerCardReveal, viaQuery.Permissions);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/test/needs-reveal")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/needs-search")).StatusCode);
    }

    // R2 – Guide §4.2 the role is read from AuthDb on every request: changing it takes effect immediately
    [Fact]
    public async Task RoleChange_TakesEffectOnNextRequest()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), (await (await LoginAsync(NewClient(), userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!.Token!);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/test/needs-reveal")).StatusCode);

        await factory.WithDbAsync(async (db, users) =>
        {
            var user = (await users.FindByIdAsync(userId))!;
            await users.RemoveFromRoleAsync(user, RoleNames.Normal);
            await users.AddToRoleAsync(user, RoleNames.Accounting);
            return 0;
        });

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/needs-reveal")).StatusCode);
    }

    // A10 – Guide §2.4 a session idle for more than 15 minutes is refused
    [Fact]
    public async Task IdleTimeout_Rejected()
    {
        var token = await SignInAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), token);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/whoami")).StatusCode);

        var idleSince = Truncate(DateTime.UtcNow.AddMinutes(-16));
        await BackdateAsync(token, s => s.SetProperty(x => x.LastSeenUtc, idleSince));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/test/whoami")).StatusCode);
    }

    // A10 – Guide §2.4 a session older than 8 hours is refused even if it was used a moment ago
    [Fact]
    public async Task AbsoluteTimeout_Rejected()
    {
        var token = await SignInAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), token);
        var created = Truncate(DateTime.UtcNow.AddHours(-9));

        await BackdateAsync(token, s => s
            .SetProperty(x => x.CreatedUtc, created)
            .SetProperty(x => x.AbsoluteExpiryUtc, created.AddHours(8)));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/test/whoami")).StatusCode);
    }

    // A10 – Guide §4.2 a disabled user's existing session stops working at once
    [Fact]
    public async Task DisabledUser_SessionRejected()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), (await (await LoginAsync(NewClient(), userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!.Token!);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/whoami")).StatusCode);

        await factory.WithDbAsync(async (db, _) => await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.IsDisabled, true)));

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/test/whoami")).StatusCode);
    }

    // A10 – Guide §2.4 logout ends the session
    [Fact]
    public async Task LoggedOutToken_Rejected()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), (await (await LoginAsync(NewClient(), userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!.Token!);

        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/auth/logout", null)).StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/test/whoami")).StatusCode);
        Assert.Equal(1, await factory.WithDbAsync((db, _) => db.AuditLogs.CountAsync(a => a.ActorUserId == userId && a.Action == AuditAction.Logout)));
    }

    // R3 – Guide §4.3 an unknown route without a session is refused with 401, not an error
    [Fact]
    public async Task UnknownRoute_WithoutSession_401() =>
        Assert.Equal(HttpStatusCode.Unauthorized, (await NewClient().GetAsync("/nothing-here")).StatusCode);

    // R3 – Guide §2.6, §4.3 while a password change is pending, permission routes are refused but logout still works
    [Fact]
    public async Task MustChangePassword_BlocksPermissionPolicies()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), (await (await LoginAsync(NewClient(), userName, AuthApiFactory.Password)).Content.ReadFromJsonAsync<LoginResponse>())!.Token!);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/test/needs-search")).StatusCode);

        await factory.WithDbAsync(async (db, users) =>
        {
            await users.AddClaimAsync((await users.FindByIdAsync(userId))!, new System.Security.Claims.Claim(PermissionCodes.MustChangePasswordClaim, "true"));
            return 0;
        });

        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync("/test/needs-search")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await client.PostAsync("/auth/logout", null)).StatusCode);
    }

    // R2 – Guide §4.2 /auth/me reports the role and permissions read from AuthDb, not anything the caller sends
    [Fact]
    public async Task Me_ReturnsRoleFromServer()
    {
        var token = await SignInAsync(RoleNames.Normal);
        var client = WithToken(NewClient(), token);
        client.DefaultRequestHeaders.Add("X-Role", RoleNames.UserAdmin);

        var me = (await (await client.GetAsync("/auth/me")).Content.ReadFromJsonAsync<MeResponse>())!;

        Assert.Equal(RoleNames.Normal, me.Role);
        Assert.Contains(PermissionCodes.CustomerSearch, me.Permissions);
        Assert.DoesNotContain(PermissionCodes.UserCreate, me.Permissions);
        Assert.False(me.MustChangePassword);
    }

    // A5 – Guide §5 login success and failure are written to the audit log without the password
    [Fact]
    public async Task Login_WritesAuditRows()
    {
        var (userId, userName) = await factory.CreateUserAsync(RoleNames.Normal);

        await LoginAsync(NewClient(), userName, "wrong-password-xyz");
        await LoginAsync(NewClient(), userName, AuthApiFactory.Password);

        var actions = await factory.WithDbAsync((db, _) =>
            db.AuditLogs.Where(a => a.ActorUserId == userId).Select(a => a.Action).ToListAsync());
        Assert.Contains(AuditAction.LoginFailed, actions);
        Assert.Contains(AuditAction.LoginSucceeded, actions);
    }

    private static DateTime Truncate(DateTime value) => new(value.Ticks - value.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);

    private Task BackdateAsync(string token, System.Linq.Expressions.Expression<Func<Microsoft.EntityFrameworkCore.Query.SetPropertyCalls<Session>, Microsoft.EntityFrameworkCore.Query.SetPropertyCalls<Session>>> change)
    {
        var hash = SHA256.HashData(WebEncoders.Base64UrlDecode(token));
        return factory.WithDbAsync(async (db, _) => await db.Sessions.Where(s => s.TokenHash == hash).ExecuteUpdateAsync(change));
    }

    private record WhoAmI(string Role, string UserId, string[] Permissions);

    private class ThrowingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("network down");
    }
}
