using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Authorize
{
    public class FirstNameRequirement : IAuthorizationRequirement
    {

        public FirstNameRequirement(string name)
        {
            Name = name;
        }

        public string Name { get; set; }
    }
}
