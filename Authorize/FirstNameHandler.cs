using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
    public class FirstNameHandler : AuthorizationHandler<FirstNameRequirement>
    {
        public UserManager<ApplicationUser> _userManager { get; set; }
        public AppDBContext _db { get; set; }

        public FirstNameHandler(UserManager<ApplicationUser> userManager, AppDBContext appDBContext)
        {
            _userManager = userManager;
            _db = appDBContext;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, FirstNameRequirement requirement)
        {
            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var user = _db.ApplicationUsers.FirstOrDefault(x => x.Id == userId);
            if(user != null)
            {
                var firstNameClaim = _userManager.GetClaimsAsync(user).GetAwaiter().GetResult().FirstOrDefault(u => u.Type == "FirstName");

                if(firstNameClaim != null)
                {
                    if (firstNameClaim.Value.ToLower().Contains(requirement.Name.ToLower()))
                    {
                        context.Succeed(requirement);
                    }
                }
            }
            return Task.CompletedTask;
        }
    }
}
