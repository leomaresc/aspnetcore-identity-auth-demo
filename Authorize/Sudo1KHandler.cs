using IdentityManager.Services.IServices;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

namespace IdentityManager.Authorize
{
    public class Sudo1KHandler : AuthorizationHandler<Sudo1K>
    {
        private readonly INumberOfDaysForAccount _numberOfDaysForAccount;

        public Sudo1KHandler(INumberOfDaysForAccount numberOfDaysForAccount)
        {
            _numberOfDaysForAccount = numberOfDaysForAccount;
        }
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, Sudo1K requirement)
        {
            if (!context.User.IsInRole(SD.Admin))
            {
                return Task.CompletedTask;
            }

            var userId = context.User.FindFirst(ClaimTypes.NameIdentifier).Value;
            var numberOfDays = _numberOfDaysForAccount.Get(userId);

            if (numberOfDays >= requirement.Days)
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
