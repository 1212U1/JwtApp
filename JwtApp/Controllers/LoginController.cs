using JwtApp.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class LoginController : ControllerBase
    {
        private readonly IConfiguration configuration;

        public LoginController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Login([FromBody] UserModel userModel)
        {
            UserProfile profile = GetUserProfile(userModel);
            if (profile == null) { return NotFound(); }
            String token = GetToken(profile);
            return Ok(token);
        }

        private String GetToken(UserProfile profile)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            Claim[] claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier,profile.Username),
                new Claim(ClaimTypes.GivenName,profile.GivenName),
                new Claim(ClaimTypes.Email,profile.GivenName),
                new Claim(ClaimTypes.Surname,profile.Surname),
                new Claim(ClaimTypes.Role,profile.Role),
            };
            JwtSecurityToken jwtSecurityToken = new JwtSecurityToken(configuration["Jwt:Issuer"],
              configuration["Jwt:Audience"],
              claims,
              expires: DateTime.Now.AddMinutes(15),
              signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }
        private UserProfile GetUserProfile(UserModel userModel)
        {
            return UserConstants.Users.FirstOrDefault(o => o.Username.ToLower() == userModel.UserName.ToLower() && o.Password == userModel.Password);
        }

    }
}
