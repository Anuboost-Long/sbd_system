namespace SBD.API.Services.Session;

public record IssuedSession(string Token, DateTime ExpiresUtc);

public interface ISessionService
{
    Task<IssuedSession> CreateAsync(string userId);
    Task RevokeAsync(long sessionId);
    Task RevokeAllAsync(string userId);
    Task RevokeOthersAsync(string userId, long keepSessionId);
}
