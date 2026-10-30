using CloudX.EntraID.Services.OrphanedAccount;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class OrphanedAccountController : Controller
{
    private readonly IOrphanedAccountService _orphanedAccountService;

    public OrphanedAccountController(
        IOrphanedAccountService orphanedAccountService)
    {
        _orphanedAccountService = orphanedAccountService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var orphanedAccounts =
            await _orphanedAccountService
                .GetOrphanedAccountsAsync();

        return View(
            "~/Views/EntraUser/OrphanedAccounts.cshtml",
            orphanedAccounts);
    }
}