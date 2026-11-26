/*
 * File: AdminController.cs
 * Implements: Guide §4.4 User Admin endpoints; each has its own permission, runs from the internal network only and sees no customer data.
 * Controls:   R6
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SBD.API.Common;
using SBD.API.Services.Admin.Dtos;
using SBD.API.Services.Admin.Functions;
using SBD.API.Services.Auth.Dtos;

namespace SBD.API.Services.Admin;

// [Guide §4.4] Every admin route needs its own user.* permission plus the AdminAccess filter.
// Why: UserAdmin has no customer.* permission, so it sees no customer data.
// Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V8.2.1.
// Evidence: tests NonAdmin_CannotCallAdmin, Admin_CannotSearch, Admin_FromExternalIp_403 (R6).
[ApiController, AdminAccess]
[Route("admin/users")]
public class AdminController(AdminService admin) : ControllerBase
{
    private string ActorId => User.FindFirstValue(ClaimTypes.NameIdentifier)!;

    [Authorize(PermissionCodes.UserCreate), HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateUserRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        var role = AdminRequestValidator.Role(request.Role, errors);
        var approvalRef = AdminRequestValidator.ApprovalRef(request.ApprovalRef, required: true, errors);
        if (string.IsNullOrEmpty(request.Username)) errors["username"] = ["Enter a username."];
        if (string.IsNullOrEmpty(request.TemporaryPassword)) errors["temporaryPassword"] = ["Enter a temporary password."];
        if (errors.Count > 0) return ValidationProblem(new ValidationProblemDetails(errors));

        var result = await admin.CreateUserAsync(ActorId, request.Username!, role!, request.TemporaryPassword!, approvalRef!);
        return result.Outcome == AdminOutcome.Ok
            ? StatusCode(StatusCodes.Status201Created, result.Created)
            : ToActionResult(result);
    }

    [Authorize(PermissionCodes.UserRoleAssign), HttpPost("{id}/role")]
    public async Task<IActionResult> AssignRole(string id, [FromBody] AssignRoleRequest request)
    {
        var errors = new Dictionary<string, string[]>();
        var role = AdminRequestValidator.Role(request.Role, errors);
        var approvalRef = AdminRequestValidator.ApprovalRef(request.ApprovalRef, required: true, errors);
        if (errors.Count > 0) return ValidationProblem(new ValidationProblemDetails(errors));

        return ToActionResult(await admin.AssignRoleAsync(ActorId, id, role!, approvalRef));
    }

    [Authorize(PermissionCodes.UserDisable), HttpPost("{id}/disable")]
    public async Task<IActionResult> Disable(string id, [FromBody] DisableUserRequest? request)
    {
        var errors = new Dictionary<string, string[]>();
        var approvalRef = AdminRequestValidator.ApprovalRef(request?.ApprovalRef, required: true, errors);
        if (errors.Count > 0) return ValidationProblem(new ValidationProblemDetails(errors));

        return ToActionResult(await admin.DisableAsync(ActorId, id, approvalRef!));
    }

    [Authorize(PermissionCodes.UserPasswordReset), HttpPost("{id}/password-reset")]
    public async Task<IActionResult> ResetPassword(string id, [FromBody] PasswordResetRequest request)
    {
        if (string.IsNullOrEmpty(request.TemporaryPassword))
            return ValidationProblem(new ValidationProblemDetails(new Dictionary<string, string[]> { ["temporaryPassword"] = ["Enter a temporary password."] }));

        return ToActionResult(await admin.ResetPasswordAsync(ActorId, id, request.TemporaryPassword));
    }

    [Authorize(PermissionCodes.UserMfaReset), HttpPost("{id}/mfa-reset")]
    public async Task<IActionResult> ResetMfa(string id) => ToActionResult(await admin.ResetMfaAsync(ActorId, id));

    [Authorize(PermissionCodes.UserSearchUnlock), HttpPost("{id}/search-unlock")]
    public async Task<IActionResult> UnlockSearch(string id) => ToActionResult(await admin.UnlockSearchAsync(ActorId, id));

    // [Guide §4.4] Own-account change gives 403, unknown target 404, failed password rules 400.
    // Why: the refusal is explicit so it can be tested and audited.
    // Standard: OWASP ASVS 5.0 V8.2.1.
    // Evidence: test Admin_CannotChangeOwnRole (R6).
    private IActionResult ToActionResult(AdminResult result) => result.Outcome switch
    {
        AdminOutcome.Ok => NoContent(),
        AdminOutcome.NotFound => NotFound(new ErrorResponse("User not found.")),
        AdminOutcome.SelfChange => StatusCode(StatusCodes.Status403Forbidden, new ErrorResponse("You cannot change your own account.")),
        _ => ValidationProblem(new ValidationProblemDetails(result.Errors!.ToDictionary(e => e.Key, e => e.Value))),
    };
}
