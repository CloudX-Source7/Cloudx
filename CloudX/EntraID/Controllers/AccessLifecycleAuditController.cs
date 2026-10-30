using CloudX.EntraID.Services.AccessLifecycleAudit;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class AccessLifecycleAuditController : Controller
{
    private readonly IAccessLifecycleAuditService
        _auditService;

    public AccessLifecycleAuditController(
        IAccessLifecycleAuditService auditService)
    {
        _auditService = auditService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var auditTrail =
            await _auditService.GetAuditTrailAsync();

        return View(
            "~/Views/EntraUser/AccessLifecycleAudit.cshtml",
            auditTrail);
    }
}