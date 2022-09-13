using AutoMapper;
using Core.DTO.Register;
using Core.Services;
using Domain.Models;
using Infrastructure.Configurations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IMapper _mapper;
    private readonly JwtConfiguration _jwtConfiguration;

    public AuthenticationService(UserManager<ApplicationUser> userManager, IMapper mapper, IOptions<JwtConfiguration> jwtConfiguration)
    {
        _userManager = userManager;
        _mapper = mapper;
        _jwtConfiguration = jwtConfiguration.Value;
    }

    public async Task<RegisterResult> RegisterAsync(RegisterCommand command)
    {
        if (await _userManager.FindByEmailAsync(command.Email) is not null)
            return new RegisterResult { Message = "email is already registered!" };

        if (await _userManager.FindByNameAsync(command.Username) is not null)
            return new RegisterResult { Message = "username is already registered!" };

        var user = _mapper.Map<ApplicationUser>(command);

        var userResult = await _userManager.CreateAsync(user, command.Password);
        if (!userResult.Succeeded)
        {
            var errorMessage = string.Empty;
            foreach (var error in userResult.Errors)
            {
                errorMessage += error.Description + "\n";
            }
            return new RegisterResult { Message = errorMessage };
        }

        var roleResult = await _userManager.AddToRoleAsync(user, ApplicationRoles.User);
        if (!roleResult.Succeeded)
        {
            var errorMessage = string.Empty;
            foreach (var error in userResult.Errors)
            {
                errorMessage += error.Description + "\n";
            }
            return new RegisterResult { Message = errorMessage };
        }

        var jwtSecurityToken = await GenerateJwtToken(user);
        var refreshToken = GenerateRefreshToken();
        user.RefreshTokens.Add(refreshToken);
        await _userManager.UpdateAsync(user);

        return new RegisterResult
        {
            Username = user.UserName,
            Email = user.Email,
            //TokenExpiration = jwtSecurityToken.ValidTo,
            IsAuthenticated = true,
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            Roles = new List<string> { ApplicationRoles.User },
            RefershTokenExpiration = refreshToken.ExpiresOn,
            RefreshToken = refreshToken.Token
        };
    }

    public async Task<RegisterResult> GetTokenAsync(TokenRequestQuery query)
    {
        var user = await _userManager.FindByEmailAsync(query.Email);

        if (user is null || !await _userManager.CheckPasswordAsync(user, query.Password))
        {
            return new RegisterResult { Message = "email or password is invalid" };
        }

        var jwtSecurityToken = await GenerateJwtToken(user);
        var roles = await _userManager.GetRolesAsync(user);

        return new RegisterResult
        {
            Username = user.UserName,
            Email = user.Email,
            //TokenExpiration = jwtSecurityToken.ValidTo,
            IsAuthenticated = true,
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            Roles = roles.ToList(),
        };
    }

    public async Task<RegisterResult> GetRefreshTokenAsync(TokenRequestQuery query)
    {
        var registerResult = new RegisterResult();

        var user = await _userManager.FindByEmailAsync(query.Email);

        if (user is null || !await _userManager.CheckPasswordAsync(user, query.Password))
        {
            registerResult.Message = "email or password is invalid";
            return registerResult;
        }

        var jwtSecurityToken = await GenerateJwtToken(user);
        var roles = await _userManager.GetRolesAsync(user);

        registerResult.Username = user.UserName;
        registerResult.Email = user.Email;
        //TokenExpiration = jwtSecurityToken.ValidTo,
        registerResult.IsAuthenticated = true;
        registerResult.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        registerResult.Roles = roles.ToList();

        if (user.RefreshTokens.Any(t => t.IsActive))
        {
            var activatedRefreshToken = user.RefreshTokens.SingleOrDefault(t => t.IsActive);
            registerResult.RefershTokenExpiration = activatedRefreshToken.ExpiresOn;
            registerResult.RefreshToken = activatedRefreshToken.Token;
        }
        else
        {
            var refreshToken = GenerateRefreshToken();
            registerResult.RefershTokenExpiration = refreshToken.ExpiresOn;
            registerResult.RefreshToken = refreshToken.Token;
            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
        }

        return registerResult;
    }

    public async Task<RegisterResult> RefreshTokenAsync(string token)
    {
        var registerResult = new RegisterResult();

        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

        if (user is null)
        {
            registerResult.Message = "invalid token";
            return registerResult;
        }

        var refreshToken = user.RefreshTokens.SingleOrDefault(t => t.Token == token);

        if (!refreshToken.IsActive)
        {
            registerResult.Message = "inactive token";
            return registerResult;
        }

        refreshToken.RevokeOn = DateTime.UtcNow;

        var newRefreshToken = GenerateRefreshToken();
        user.RefreshTokens.Add(refreshToken);
        await _userManager.UpdateAsync(user);

        var newJwtToken = await GenerateJwtToken(user);
        var roles = await _userManager.GetRolesAsync(user);

        registerResult.Username = user.UserName;
        registerResult.Email = user.Email;
        registerResult.IsAuthenticated = true;
        registerResult.Token = new JwtSecurityTokenHandler().WriteToken(newJwtToken);
        registerResult.Roles = roles.ToList();
        registerResult.RefreshToken = newRefreshToken.Token;
        registerResult.RefershTokenExpiration = newRefreshToken.ExpiresOn;

        return registerResult;
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

        if (user is null)
        {
            return false;
        }

        var refreshToken = user.RefreshTokens.SingleOrDefault(t => t.Token == token);

        if (!refreshToken.IsActive)
        {
            return false;
        }

        refreshToken.RevokeOn = DateTime.UtcNow;

        await _userManager.UpdateAsync(user);

        return true;
    }

    private async Task<JwtSecurityToken> GenerateJwtToken(ApplicationUser user)
    {
        var userClaims = await _userManager.GetClaimsAsync(user);
        var roles = await _userManager.GetRolesAsync(user);
        var roleClaims = new List<Claim>();

        foreach (var role in roles)
        {
            roleClaims.Add(new Claim("role", role));
        }

        var claims = new Claim[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email),
            new Claim("Uid", user.Id),
        }
        .Union(userClaims)
        .Union(roleClaims);

        var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Key));
        var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

        var jwtSecurityToken = new JwtSecurityToken(
            issuer: _jwtConfiguration.Issuer,
            audience: _jwtConfiguration.Audience,
            claims: claims,
            expires: DateTime.Now.AddDays(_jwtConfiguration.DurationInDays),
            signingCredentials: signingCredentials
            );

        return jwtSecurityToken;
    }

    private RefreshToken GenerateRefreshToken()
    {
        var randomNumber = new byte[32];

        using var generator = new RNGCryptoServiceProvider();

        generator.GetBytes(randomNumber);

        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomNumber),
            ExpiresOn = DateTime.UtcNow.AddDays(10),
            CreatedOn = DateTime.UtcNow,
        };
    }

}
