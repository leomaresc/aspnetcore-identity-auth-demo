using IdentityManager.Data;
using IdentityManager.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    public class RoleController : Controller
    {
        private readonly AppDBContext _db;
        private readonly UserManager<ApplicationUser> _usermanager;
        private readonly RoleManager<IdentityRole> _roleManager;

        public RoleController(AppDBContext db, UserManager<ApplicationUser> usermanager, RoleManager<IdentityRole> roleManager)
        {
            _db = db;
            _usermanager = usermanager;
            _roleManager = roleManager;
        }

        public IActionResult Index()
        {
            var roles = _db.Roles.ToList();

            return View(roles);
        }
        [HttpGet]
        public IActionResult Upsert(string roleId)
        {
            if (string.IsNullOrEmpty(roleId))
            {
                return View();
            }
            else
            {
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
                return View(objFromDb);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upsert(IdentityRole roleObj)
        {
            if(await _roleManager.RoleExistsAsync(roleObj.Name))
            {
                //Error
            }
            if (String.IsNullOrEmpty(roleObj.NormalizedName))
            {
                await _roleManager.CreateAsync(new IdentityRole() { Name = roleObj.Name });
                TempData[SD.Success] = "Se ha creado el rol de manera exitosa";
            }
            else
            {
                var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleObj.Id);
                objFromDb.Name = roleObj.Name;
                objFromDb.NormalizedName = roleObj.Name.ToUpper();
                var result = await _roleManager.UpdateAsync(objFromDb);
                TempData[SD.Success] = "Se ha actualizado el rol con exito";
            }
            return RedirectToAction(nameof(Index));
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Delete(string roleId)
        {
            var objFromDb = _db.Roles.FirstOrDefault(u => u.Id == roleId);
            if (objFromDb != null)
            {

                var userRolesForThisRole = _db.UserRoles.Where(u => u.RoleId == roleId).Count();
                if (userRolesForThisRole > 0)
                {
                    TempData[SD.Error] = "No se puede eliminar este rol. Hay usuarios activos con este rol.";
                    return RedirectToAction(nameof(Index));
                }

                var result = await _roleManager.DeleteAsync(objFromDb);
                TempData[SD.Success] = "Se ha eliminado el rol de manera exitosa";
            }
            return RedirectToAction(nameof(Index));
        }

    }
}
