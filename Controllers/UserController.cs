using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly AppDBContext _db;
        private readonly UserManager<ApplicationUser> _usermanager;

        public UserController(AppDBContext db, UserManager<ApplicationUser> usermanager)
        {
            _db = db;
            _usermanager = usermanager;
        }

        public IActionResult Index()
        {
            var userList = _db.ApplicationUsers.ToList();
            var userRoles = _db.UserRoles.ToList();
            var roles = _db.Roles.ToList();

            foreach (var user in userList)
            {
                var user_role = userRoles.FirstOrDefault(u => u.UserId == user.Id);
                if(user_role == null)
                {
                    user.Role = "none";
                }
                else
                {
                    user.Role = roles.FirstOrDefault(r => r.Id == user_role.RoleId).Name;
                }
            }

            return View(userList);
        }
    }
}
