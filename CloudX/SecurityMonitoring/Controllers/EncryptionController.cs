using CloudX.SecurityMonitoring.Services.Encryption;
using CloudX.SecurityMonitoring.UniversalRuleSupport;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
public class EncryptionController : Controller
{
    private readonly IEncryptionService _service;

    public EncryptionController(
        IEncryptionService service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> StorageEncryption()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageEncryptionAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            // Log the real exception internally
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "StorageEncryption",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> StorageCustomerManagedKey()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageCustomerManagedKeyAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            // Log the real exception internally
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "StorageCustomerManagedKey",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlEncryption()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlEncryptionAsync(entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            // Log the real exception internally
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "SqlEncryption",
                    "",
                    "",
                    "Microsoft.Sql/servers/databases",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlCustomerManagedKey()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlCustomerManagedKeyAsync(
                        entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            // Log the real exception internally
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "SqlCustomerManagedKey",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultKeyProtection()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultKeyProtectionAsync(
                        entraTenantId);

            return View(
                "~/Views/SecurityMonitoring/SecurityScanResult.cshtml",
                findings);
        }
        catch (Exception ex)
        {
            // Log the real exception internally
            Console.WriteLine(ex);

            return View(
                "~/Views/SecurityMonitoring/NotEvaluated.cshtml",
                UniversalResult.NotEvaluated(
                    "KeyVaultKeyProtection",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
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
    public async Task<IActionResult> WebAppTls()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppTlsAsync(entraTenantId);

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
                    "WebAppTls",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
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
                    "EncryptionScan",
                    "",
                    "",
                    "",
                    "CloudX could not complete the encryption security scan."));
        }
    }
}