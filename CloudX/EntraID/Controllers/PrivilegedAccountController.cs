using CloudX.EntraID.Services.PrivilegedAccount;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class PrivilegedAccountController : Controller
{
    private readonly IPrivilegedAccountService
        _privilegedAccountService;

    public PrivilegedAccountController(
        IPrivilegedAccountService privilegedAccountService)
    {
        _privilegedAccountService =
            privilegedAccountService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var findings =
            await _privilegedAccountService
                .GetPrivilegedAccountsAsync();

        return View(
            "~/Views/EntraUser/PrivilegedAccounts.cshtml",
            findings);
    }
}