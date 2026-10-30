using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.Start.Controllers;

public class StartController : Controller
{
    [AllowAnonymous]
    public IActionResult Index()
    {
        return View("~/Views/Start/Start.cshtml");
    }
}