using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Authorize
{
    public class OnlySudoAdminChecker : AuthorizationHandler<OnlySudoAdminChecker>, IAuthorizationRequirement
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, OnlySudoAdminChecker requirement)
        {
            if (context.User.IsInRole(SD.Admin_Sudo))
            {
                context.Succeed(requirement);
                return Task.CompletedTask;
            }
            return Task.CompletedTask;
        }
    }
}
