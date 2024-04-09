using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RestoCommand.Models.Authentication;
using RestoCommandAPI.Authentication;
using RestoCommandAPI.Database;

namespace RestoCommandAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticateController(ApplicationDbContext context, RoleManager<IdentityRole> roleManager, IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _context = context;
            _roleManager = roleManager;
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] UserInfo model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var authSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();
        }

        // POST: api/register
        // To protect from overposting attacks, see https://go.microsoft.com/fwlink/?linkid=2123754
        [HttpPost]
        [Route("register")]
        public async Task<ActionResult<UserInfo>> Register([FromBody] UserInfo userInfo)
        {
            var userExists = await _userManager.FindByEmailAsync(userInfo.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new ApplicationUser()
            {
                UserName = userInfo.Email,
                Email = userInfo.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };

            try
            {
                IdentityResult result = await _userManager.CreateAsync(user, userInfo.Password);
                string errors = string.Empty;

                foreach (IdentityError error in result.Errors)
                {
                    errors += error.Description + "\n"; 
                }
                if (!result.Succeeded)
                    return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! \\n " + errors });

                if (!await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin.ToString()));
                if (!await _roleManager.RoleExistsAsync(UserRoles.User.ToString()))
                    await _roleManager.CreateAsync(new IdentityRole(UserRoles.User.ToString()));

                if (await _roleManager.RoleExistsAsync(UserRoles.User.ToString()))
                {
                    await _userManager.AddToRoleAsync(user, UserRoles.User.ToString());
                }

                return Ok(new Response { Status = "Success", Message = "User created successfully!" });
            }
            catch (Exception e)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! \\n " + e.Message });
            }
        }

        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] UserInfo model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            ApplicationUser user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin.ToString()));
            if (!await _roleManager.RoleExistsAsync(UserRoles.User.ToString()))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User.ToString()));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin.ToString()))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin.ToString());
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }
    }
}
