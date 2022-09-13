using Core.DTO.Register;
using Core.Services;
using Microsoft.AspNetCore.Mvc;

namespace Application.Controllers
{
    //[Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        public readonly IAuthenticationService _authenticationService;

        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
        }

        [HttpPost(ApiRoutes.Authentication.Register)]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterCommand command)
        {
            var result = await _authenticationService.RegisterAsync(command);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            SetRefreshTokenInCookie(result.RefreshToken, result.RefershTokenExpiration);

            return Ok(result);
        }

        [HttpGet(ApiRoutes.Authentication.GetToken)]
        public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestQuery query)
        {
            //var result = await _authenticationService.GetTokenAsync(query);
            var result = await _authenticationService.GetRefreshTokenAsync(query);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            if (!string.IsNullOrEmpty(result.RefreshToken))
            {
                SetRefreshTokenInCookie(result.RefreshToken, result.RefershTokenExpiration);
            }

            return Ok(result);
        }

        [HttpGet(ApiRoutes.Authentication.RefreshToken)]
        public async Task<IActionResult> RefreshTokenAsync()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var result = await _authenticationService.RefreshTokenAsync(refreshToken);

            if (!result.IsAuthenticated)
            {
                return BadRequest(result.Message);
            }

            SetRefreshTokenInCookie(result.RefreshToken, result.RefershTokenExpiration);

            return Ok(result);
        }

        [HttpPost(ApiRoutes.Authentication.RevokeToken)]
        public async Task<IActionResult> RevokeTokenPostAsync(RevokeTokenCommand command)
        {
            var token = command.Token ?? Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(token))
            {
                return BadRequest("token is required");
            }

            var result = await _authenticationService.RevokeTokenAsync(token);

            if (!result)
            {
                return BadRequest("token is invalid");
            }

            return Ok();
        }

        private void SetRefreshTokenInCookie(string refershToken, DateTime expirationDate)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expirationDate.ToLocalTime(),
            };
            Response.Cookies.Append("refreshToken", refershToken, cookieOptions);
        }
    }
}
