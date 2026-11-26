namespace SBD.API.Services.Captcha;

public interface ICaptchaVerifier
{
    Task<bool> VerifyAsync(string token, string? clientIp);
}
