using CloudX.EntraID.Services.MfaEnforcement;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class MfaEnforcementController : Controller
{
    private readonly IMfaEnforcementService _mfaEnforcementService;

    public MfaEnforcementController(
        IMfaEnforcementService mfaEnforcementService)
    {
        _mfaEnforcementService = mfaEnforcementService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var findings =
            await _mfaEnforcementService
                .GetMfaFindingsAsync();

        return View(
            "~/Views/EntraUser/MfaEnforcement.cshtml",
            findings);
    }
}