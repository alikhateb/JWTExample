using Core.DTO.Register;

namespace Core.Services;

public interface IAuthenticationService
{
    Task<RegisterResult> RegisterAsync(RegisterCommand command);
    Task<RegisterResult> GetTokenAsync(TokenRequestQuery query);
    Task<RegisterResult> GetRefreshTokenAsync(TokenRequestQuery query);
    Task<RegisterResult> RefreshTokenAsync(string token);
    Task<bool> RevokeTokenAsync(string token);
}
