using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize]
public class SecurityScanController : Controller
{
    [HttpGet]
    public IActionResult Index()
    {
        return View(
            "~/Views/SecurityMonitoring/SecurityScanIndex.cshtml");
    }
}