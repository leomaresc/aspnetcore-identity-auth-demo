using Microsoft.AspNetCore.Authorization;

namespace IdentityManager.Authorize
{
    public class Sudo1K : IAuthorizationRequirement
    {

        public Sudo1K(int days)
        {
            Days = days;
        }

        public int Days { get; set; }
    }
}
