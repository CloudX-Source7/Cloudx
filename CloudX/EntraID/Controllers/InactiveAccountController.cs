using CloudX.EntraID.Services.InactiveUser;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class InactiveAccountController : Controller
{
    private readonly IInactiveAccountService _inactiveAccountService;

    public InactiveAccountController(
        IInactiveAccountService inactiveAccountService)
    {
        _inactiveAccountService = inactiveAccountService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        try
        {
            var inactiveAccounts =
                await _inactiveAccountService
                    .GetInactiveAccountsAsync(90);

            return View(
                "~/Views/EntraUser/InactiveAccounts.cshtml",
                inactiveAccounts);
        }
        catch (InvalidOperationException ex)
        {
            ViewBag.ErrorMessage = ex.Message;

            return View(
                "~/Views/EntraUser/InactiveAccounts.cshtml",
                new List<CloudX.EntraID.DTOs.InactiveAccountDto>());
        }
    }
}