using JwtApp.Model;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace JwtApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [HttpGet]
        public IActionResult PublicMethod()
        {
            return Ok("Anyone can access this resource");

        }
        [Route("admin")]
        [HttpGet]
        [Authorize(Roles = "Administrator")]
        public IActionResult AdminMethod()
        {
            UserProfile profile = GetCurrentUser();
            return Ok(profile);
        }
        [Route("seller")]
        [HttpGet]
        [Authorize(Roles = "Seller")]
        public IActionResult SellerMethod()
        {
            UserProfile profile = GetCurrentUser();
            return Ok(profile);
        }
        private UserProfile GetCurrentUser()
        {
            var identity = HttpContext.User.Identity as ClaimsIdentity;

            if (identity != null)
            {
                var userClaims = identity.Claims;

                return new UserProfile
                {
                    Username = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.NameIdentifier)?.Value,
                    EmailAddress = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Email)?.Value,
                    GivenName = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.GivenName)?.Value,
                    Surname = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Surname)?.Value,
                    Role = userClaims.FirstOrDefault(o => o.Type == ClaimTypes.Role)?.Value
                };
            }
            return null;
        }
    }
}
