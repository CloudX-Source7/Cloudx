using CloudX.EntraID.Services.ExcessivePrivilege;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class ExcessivePrivilegeController : Controller
{
    private readonly IExcessivePrivilegeService
        _excessivePrivilegeService;

    public ExcessivePrivilegeController(
        IExcessivePrivilegeService excessivePrivilegeService)
    {
        _excessivePrivilegeService =
            excessivePrivilegeService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var findings =
            await _excessivePrivilegeService
                .GetExcessivePrivilegeFindingsAsync();

        return View(
            "~/Views/EntraUser/ExcessivePrivileges.cshtml",
            findings);
    }
}