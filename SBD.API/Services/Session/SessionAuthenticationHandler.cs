/*
 * File: SessionAuthenticationHandler.cs
 * Implements: Guide §2.4, §4.2, §4.4 every request is checked against the session table and the role is read from AuthDb.
 * Controls:   A10, R2
 */
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SBD.API.Common;
using SBD.API.Contexts;

namespace SBD.API.Services.Session;

public class SessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    AuthDbContext authDb,
    TimeProvider time)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Session";
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(15);

    // [Guide §2.4, §4.2, §4.4] Every request: look up the session by token hash, refuse if revoked, over 8 h, idle over 15 min, or user disabled/locked; role and permissions come from AuthDb.
    // Why: the role cannot be forged by the client, and a role change or disable applies on the next request.
    // Standard: OWASP ASVS 5.0 V8.3.1; OWASP Session Management Cheat Sheet.
    // Evidence: tests ForgedRole_Ignored, IdleTimeout_Rejected, AbsoluteTimeout_Rejected, DisabledUser_SessionRejected (A10, R2).
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return AuthenticateResult.NoResult();

        byte[] token;
        try { token = WebEncoders.Base64UrlDecode(header["Bearer ".Length..].Trim()); }
        catch (FormatException) { return AuthenticateResult.Fail("Invalid session."); }

        var hash = SessionService.HashToken(token);
        var session = await authDb.Sessions.FirstOrDefaultAsync(s => s.TokenHash == hash);
        var now = time.GetUtcNow().UtcDateTime;

        if (session is null || session.RevokedUtc is not null
            || now >= session.AbsoluteExpiryUtc || now - session.LastSeenUtc > IdleTimeout)
            return AuthenticateResult.Fail("Invalid session.");

        var user = await authDb.Users.FirstOrDefaultAsync(u => u.Id == session.UserId);
        if (user is null || user.IsDisabled || (user.LockoutEnd is not null && user.LockoutEnd > now))
            return AuthenticateResult.Fail("Invalid session.");

        var role = await (from userRole in authDb.UserRoles
                          join r in authDb.Roles on userRole.RoleId equals r.Id
                          where userRole.UserId == user.Id
                          select new { r.Id, r.Name }).SingleOrDefaultAsync();
        if (role?.Name is null)
            return AuthenticateResult.Fail("Invalid session.");

        var permissions = await (from rolePermission in authDb.RolePermissions
                                 join p in authDb.Permissions on rolePermission.PermissionId equals p.PermissionId
                                 where rolePermission.RoleId == role.Id
                                 select p.Code).ToListAsync();
        var dataConnection = await authDb.RoleDataAccesses
            .Where(a => a.RoleId == role.Id).Select(a => a.ConnectionName).FirstOrDefaultAsync();
        var mustChangePassword = await authDb.UserClaims
            .AnyAsync(c => c.UserId == user.Id && c.ClaimType == PermissionCodes.MustChangePasswordClaim);

        session.LastSeenUtc = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerSecond, DateTimeKind.Utc);
        await authDb.SaveChangesAsync();

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Name, user.UserName ?? string.Empty),
            new(ClaimTypes.Role, role.Name),
            new(PermissionCodes.SessionIdClaim, session.SessionId.ToString()),
        };
        claims.AddRange(permissions.Select(code => new Claim(PermissionCodes.PermissionClaim, code)));
        if (dataConnection is not null) claims.Add(new Claim(PermissionCodes.DataConnectionClaim, dataConnection));
        if (mustChangePassword) claims.Add(new Claim(PermissionCodes.MustChangePasswordClaim, "true"));

        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
    }
}
