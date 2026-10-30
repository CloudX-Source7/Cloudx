using CloudX.EntraID.Services.EntraUser;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class EntraUserController : Controller
{
    private readonly IEntraUserService _userService;

    public EntraUserController(
        IEntraUserService userService)
    {
        _userService = userService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var users = await _userService.GetUsersAsync();

        return View(
            "~/Views/EntraUser/Index.cshtml",
            users);
    }
}