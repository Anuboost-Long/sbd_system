/*
 * File: AuthController.cs
 * Implements: Guide §2.4, §2.5, §2.6 login, MFA, logout and change-password endpoints; every credential failure returns one generic reply.
 * Controls:   A5, A8, A10, R6
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SBD.API.Common;
using SBD.API.Services.Auth.Dtos;
using SBD.API.SetUp;

namespace SBD.API.Services.Auth;

[ApiController]
[Route("auth")]
public class AuthController(AuthService service) : ControllerBase
{
    [AllowAnonymous, EnableRateLimiting(RateLimitSetup.LoginPolicy), HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginRequest request) =>
        ToActionResult(await service.LoginAsync(request));

    [AllowAnonymous, EnableRateLimiting(RateLimitSetup.LoginPolicy), HttpPost("mfa/setup")]
    public async Task<IActionResult> StartMfaSetup([FromBody] MfaTicketRequest request)
    {
        var setup = await service.StartMfaSetupAsync(request.MfaTicket);
        return setup is null ? ToActionResult(AuthResult.Fail(AuthFailure.InvalidTicket)) : Ok(setup);
    }

    [AllowAnonymous, EnableRateLimiting(RateLimitSetup.LoginPolicy), HttpPost("mfa/confirm")]
    public async Task<IActionResult> ConfirmMfaSetup([FromBody] MfaCodeRequest request) =>
        ToActionResult(await service.ConfirmMfaSetupAsync(request));

    [AllowAnonymous, EnableRateLimiting(RateLimitSetup.LoginPolicy), HttpPost("mfa")]
    public async Task<IActionResult> VerifyMfa([FromBody] MfaCodeRequest request) =>
        ToActionResult(await service.VerifyMfaAsync(request));

    // [Guide §2.4] Logout revokes the caller's session, so the token stops working at once, and writes a Logout audit row.
    // Why: a user must be able to end a session; the server, not the browser, decides it is over.
    // Standard: OWASP Session Management Cheat Sheet.
    // Evidence: test LoggedOutToken_Rejected (A10).
    [Authorize(PermissionCodes.SessionPolicy), HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await service.LogoutAsync(
            User.FindFirstValue(ClaimTypes.NameIdentifier)!,
            long.Parse(User.FindFirstValue(PermissionCodes.SessionIdClaim)!));
        return NoContent();
    }

    // [Guide §4.2] Tell the front end who the caller is, using the role and permissions the server just read from AuthDb.
    // Why: the page shows only what the role allows, without trusting anything the browser holds.
    // Standard: OWASP ASVS 5.0 V8.3.1.
    // Evidence: test Me_ReturnsRoleFromServer (R2).
    [Authorize(PermissionCodes.SessionPolicy), HttpGet("me")]
    public IActionResult Me() => Ok(new MeResponse(
        User.FindFirstValue(ClaimTypes.Name)!,
        User.FindFirstValue(ClaimTypes.Role)!,
        User.HasClaim(PermissionCodes.MustChangePasswordClaim, "true"),
        User.FindAll(PermissionCodes.PermissionClaim).Select(c => c.Value).Order().ToList()));

    // [Guide §2.6] Change-password needs only a valid session, so a user flagged must-change can reach it; it is rate limited like login.
    // Why: the only way out of the forced-change state, and a stolen token cannot guess the current password without limit.
    // Standard: NIST SP 800-63B-4; OWASP ASVS 5.0 V6.3.1.
    // Evidence: tests PasswordReset_ForcesChange_RevokesSessions, ChangePassword_WrongCurrent_Rejected (R6).
    [Authorize(PermissionCodes.SessionPolicy), EnableRateLimiting(RateLimitSetup.LoginPolicy), HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
    {
        var error = await service.ChangePasswordAsync(
            User.FindFirstValue(ClaimTypes.NameIdentifier)!,
            long.Parse(User.FindFirstValue(PermissionCodes.SessionIdClaim)!),
            request);
        return error is null ? NoContent() : BadRequest(new ErrorResponse(error));
    }

    // [Guide §2.5] Every credential failure (unknown user, wrong password, locked, disabled) returns the same status and the same body.
    // Why: the reply must not reveal whether a username exists, is locked or is disabled. The CAPTCHA reply is separate and applies to unknown names too.
    // Standard: OWASP ASVS 5.0 V6.3.8.
    // Evidence: test WrongUser_And_WrongPassword_SameResponse (A5).
    private IActionResult ToActionResult(AuthResult result) => result.Failure switch
    {
        AuthFailure.None => Ok(result.Response),
        AuthFailure.CaptchaRequired => Unauthorized(new ErrorResponse("Complete the verification and try again.", CaptchaRequired: true)),
        AuthFailure.InvalidCode => Unauthorized(new ErrorResponse("Invalid code.")),
        AuthFailure.InvalidTicket => Unauthorized(new ErrorResponse("Sign in again.")),
        _ => Unauthorized(new ErrorResponse("Invalid username or password.")),
    };
}
