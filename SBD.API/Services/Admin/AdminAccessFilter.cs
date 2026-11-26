/*
 * File: AdminAccessFilter.cs
 * Implements: Guide §4.4 admin endpoints answer only from the internal network and only to an account enrolled in MFA.
 * Controls:   R6
 */
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Options;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Audit;
using SBD.API.SetUp;

namespace SBD.API.Services.Admin;

public class AdminAccessAttribute() : TypeFilterAttribute(typeof(AdminAccessFilter));

public class AdminAccessFilter(
    IOptions<SecurityOptions> options,
    UserManager<ApplicationUser> users,
    IAuditLogger audit) : IAsyncAuthorizationFilter
{
    private readonly IReadOnlySet<IPAddress> adminIps = SecurityOptions.ParseIps(options.Value.AdminAllowedIps);

    // [Guide §4.4] Admin routes need an internal-network address and an account with MFA; otherwise 403 and an audit row.
    // Why: small attack surface. The address is read from the connection, not from headers.
    // Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V6.3.3, V8.2.1.
    // Evidence: tests Admin_FromExternalIp_403, Admin_WithoutMfa_403 (R6).
    public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
    {
        var callerId = context.HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var remote = context.HttpContext.Connection.RemoteIpAddress?.MapToIPv6();

        var internalNetwork = remote is not null && adminIps.Contains(remote);
        var caller = callerId is null ? null : await users.FindByIdAsync(callerId);
        if (internalNetwork && caller is { TwoFactorEnabled: true }) return;

        await audit.LogAsync(AuditAction.AccessDenied, AuditOutcome.Denied, callerId);
        context.Result = new StatusCodeResult(StatusCodes.Status403Forbidden);
    }
}
