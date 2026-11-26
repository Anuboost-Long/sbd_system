namespace SBD.API.Services.Admin.Dtos;

public record CreateUserRequest(string? Username, string? Role, string? TemporaryPassword, string? ApprovalRef);

public record AssignRoleRequest(string? Role, string? ApprovalRef);

public record DisableUserRequest(string? ApprovalRef);

public record PasswordResetRequest(string? TemporaryPassword);

public record CreatedUserResponse(string UserId, string Username, string Role);
