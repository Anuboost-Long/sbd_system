using SBD.API.Services.Auth.Dtos;

namespace SBD.API.Services.Auth;

public enum AuthFailure
{
    None,
    InvalidCredentials,
    CaptchaRequired,
    InvalidCode,
    InvalidTicket,
}

public record AuthResult(LoginResponse? Response, AuthFailure Failure = AuthFailure.None)
{
    public static AuthResult Ok(LoginResponse response) => new(response);
    public static AuthResult Fail(AuthFailure failure) => new(null, failure);
}
