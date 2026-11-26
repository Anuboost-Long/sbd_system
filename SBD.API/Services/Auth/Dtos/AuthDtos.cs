namespace SBD.API.Services.Auth.Dtos;

public record LoginRequest(string? Username, string? Password, string? CaptchaToken);

public record MfaTicketRequest(string? MfaTicket);

public record MfaCodeRequest(string? MfaTicket, string? Code);

public record LoginResponse(
    string? Token = null,
    DateTime? ExpiresUtc = null,
    bool MfaRequired = false,
    bool MfaSetupRequired = false,
    string? MfaTicket = null);

public record ChangePasswordRequest(string? CurrentPassword, string? NewPassword);

public record MfaSetupResponse(string ManualKey);

public record ErrorResponse(string Error, bool CaptchaRequired = false);

public record MeResponse(string Username, string Role, bool MustChangePassword, IReadOnlyList<string> Permissions);
