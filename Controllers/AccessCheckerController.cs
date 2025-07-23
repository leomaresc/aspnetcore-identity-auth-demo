using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace IdentityManager.Controllers
{
    [Authorize]
    public class AccessCheckerController : Controller
    {
        //Todos puedes acceder
        [AllowAnonymous]
        public IActionResult AllAccess()
        {
            return View();
        }

        //Solo logeados puedes acceder
        public IActionResult AuthorizedAccess()
        {
            return View();
        }

        //Solo usuarios con rol User o admin pueden accederoo
        [Authorize(Roles = $"{SD.Admin}, {SD.User}")]
        public IActionResult UserORAdminRoleAccess()
        {
            return View();
        }

        //Solo usuarios con rol User y admin pueden acceder
        [Authorize(Policy = "AdminAndUser")]
        public IActionResult UserANDAdminRoleAccess()
        {
            return View();
        }

        //Solo administradores pueden acceder
        [Authorize(Policy = "Admin")]
        public IActionResult AdminRoleAccess()
        {
            return View();
        }

        //Solo administradores con Claim de creación pueden acceder
        [Authorize(Policy = "AdminRole_CreateClaim")]
        public IActionResult Admin_CreateAccess()
        {
            return View();
        }

        //Solo administradores con Claim de creación y actualización y borrar pueden acceder (DEBEN TENER TODOS LOS CLAIMS)
        [Authorize(Policy = "AdminRole_AllClaims")]
        public IActionResult Admin_Create_Edit_DeleteAccess()
        {
            return View();
        }

        //Solo administradores con Claim de creación y actualización y borrar pueden acceder (DEBEN TENER TODOS LOS CLAIMS)
        [Authorize(Policy = "AdminRole_Sudo")]
        public IActionResult Admin_Sudo()
        {
            return View();
        }

        [Authorize(Policy = "Sudo1K")]
        public IActionResult SoloLeomar()
        {
            return View();
        }

        [Authorize(Policy = "FirstNameAuth")]
        public IActionResult FirstNameAuth()
        {
            return View();
        }
    }
}
