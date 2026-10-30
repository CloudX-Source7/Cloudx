using CloudX.SecurityMonitoring.Services.IdentityAccess;
using CloudX.SecurityMonitoring.UniversalRuleSupport;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
public class IdentityAccessController : Controller
{
    private readonly IIdentityAccessService _service;

    public IdentityAccessController(
        IIdentityAccessService service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> WebAppManagedIdentity()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppManagedIdentityAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "WebAppManagedIdentity",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppAuthentication()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppAuthenticationAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "WebAppAuthentication",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultAccessPolicy()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultAccessPolicyAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "KeyVaultAccessPolicy",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultRbac()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultRbacAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "KeyVaultRbac",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> StorageRbac()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageRbacAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "StorageRbac",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlAuthentication()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlAuthenticationAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "SqlAuthentication",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    private string? GetTenantId()
    {
        return User.FindFirstValue("tid")
            ?? User.FindFirstValue(
                "http://schemas.microsoft.com/identity/claims/tenantid");
    }
    [HttpGet]
    public async Task<IActionResult> Scan()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .ScanAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanSummary.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "IdentityAccessScan",
                    "",
                    "",
                    "",
                    "CloudX could not complete the identity and access security scan."));
        }
    }
}