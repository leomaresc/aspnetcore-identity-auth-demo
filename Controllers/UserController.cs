using IdentityManager.Data;
using IdentityManager.Models;
using IdentityManager.Models.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityManager.Controllers
{
    public class UserController : Controller
    {
        private readonly AppDBContext _db;
        private readonly UserManager<ApplicationUser> _usermanager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public UserController(AppDBContext db, UserManager<ApplicationUser> usermanager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _usermanager = usermanager;
            _roleManager = roleManager;
        }

        public async Task<IActionResult> Index()
        {
            var userList = _db.ApplicationUsers.ToList();

            foreach (var user in userList)
            {
                var user_role = await _usermanager.GetRolesAsync(user) as List<String>;
                user.Role = String.Join(", ", user_role);

                var user_claim = _usermanager.GetClaimsAsync(user).GetAwaiter().GetResult().Select(u => u.Type);
                user.UserClaim = String.Join(", ", user_claim);
            }

            return View(userList);
        }

        // -------------------
        // Administrar roles
        // -------------------

        public async Task<IActionResult> ManageRole(string userId)
        {
            ApplicationUser user = await _usermanager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            List<string> existingUserRoles = await _usermanager.GetRolesAsync(user) as List<string>;
            var model = new RolesViewModel()
            {
                User = user
            };

            foreach(var role in _roleManager.Roles)
            {
                RoleSelection roleSelection = new()
                {
                    RoleName = role.Name
                };
                if(existingUserRoles.Any(c => c == role.Name))
                {
                    roleSelection.IsSelected = true;
                }
                model.RolesList.Add(roleSelection);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRole(RolesViewModel rolesViewModel)
        {
            ApplicationUser user = await _usermanager.FindByIdAsync(rolesViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldUserRoles = await _usermanager.GetRolesAsync(user);
            var result = await _usermanager.RemoveFromRolesAsync(user, oldUserRoles);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error al intentar remover roles.";
                return View(rolesViewModel);
            }

            result = await _usermanager.AddToRolesAsync(user, rolesViewModel.RolesList.Where(x => x.IsSelected).Select(y => y.RoleName));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error al intentar agregar roles.";
                return View(rolesViewModel);
            }

            TempData[SD.Success] = "Roles actualizados correctamente.";

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LockUnlock(string userId)
        {
            ApplicationUser user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if (user == null)
            {
                return NotFound();
            }

            if(user.LockoutEnd != null && user.LockoutEnd > DateTime.Now)
            {
                user.LockoutEnd = DateTime.Now;
                TempData[SD.Success] = "Usuario desbloqueado de manera exitosa.";
            }
            else
            {
                user.LockoutEnd = DateTime.Now.AddYears(1000);
                TempData[SD.Success] = "Usuario bloqueado de manera exitosa.";
            }
            _db.SaveChanges();

            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteUser(string userId)
        {
            var user = _db.ApplicationUsers.FirstOrDefault(u => u.Id == userId);
            if(user == null)
            {
                return NotFound();
            }

            _db.ApplicationUsers.Remove(user);
            _db.SaveChanges();
            TempData[SD.Success] = "El usuario ha sido eliminado";

            return RedirectToAction(nameof(Index));
        }


        // -------------------
        // Administrar claims
        // -------------------

        public async Task<IActionResult> ManageUserClaim(string userId)
        {
            ApplicationUser user = await _usermanager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound();
            }

            var existingUserClaims = await _usermanager.GetClaimsAsync(user);
            var model = new ClaimsViewModel()
            {
                User = user
            };

            foreach (Claim claim in ClaimStore.claimsList)
            {
                ClaimSelection userClaim = new()
                {
                    ClaimType = claim.Type
                };
                if (existingUserClaims.Any(c => c.Type == claim.Type))
                {
                    userClaim.IsSelected = true;
                }
                model.ClaimList.Add(userClaim);
            }
            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageUserClaim(ClaimsViewModel claimsViewModel)
        {
            ApplicationUser user = await _usermanager.FindByIdAsync(claimsViewModel.User.Id);
            if (user == null)
            {
                return NotFound();
            }

            var oldClaims = await _usermanager.GetClaimsAsync(user);
            var result = await _usermanager.RemoveClaimsAsync(user, oldClaims);
            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error al intentar remover claims.";
                return View(claimsViewModel);
            }

            result = await _usermanager.AddClaimsAsync(user, claimsViewModel.ClaimList.Where(x => x.IsSelected).Select(y => new Claim(y.ClaimType, y.IsSelected.ToString())));

            if (!result.Succeeded)
            {
                TempData[SD.Error] = "Error al intentar agregar claims.";
                return View(claimsViewModel);
            }

            TempData[SD.Success] = "Claims actualizados correctamente.";

            return RedirectToAction(nameof(Index));
        }
    }
}
