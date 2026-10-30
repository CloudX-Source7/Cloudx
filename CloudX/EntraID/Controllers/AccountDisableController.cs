using CloudX.EntraID.Services.AccountDisable;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class AccountDisableController : Controller
{
    private readonly IAccountDisableService
        _accountDisableService;

    public AccountDisableController(
        IAccountDisableService accountDisableService)
    {
        _accountDisableService =
            accountDisableService;
    }

    [HttpGet]
    public IActionResult Index()
    {
        return View(
            "~/Views/EntraUser/AccountDisable.cshtml");
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Disable(
        string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            return BadRequest(
                "User ID is required.");
        }

        try
        {
            var result =
                await _accountDisableService
                    .DisableAccountAsync(userId);

            TempData["DisableResult"] =
                result.Message;

            return RedirectToAction(
                nameof(Index));
        }
        catch (Exception ex)
        {
            TempData["DisableError"] =
                ex.Message;

            return RedirectToAction(
                nameof(Index));
        }
    }
}