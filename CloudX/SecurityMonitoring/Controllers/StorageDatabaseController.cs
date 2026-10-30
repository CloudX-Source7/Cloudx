using CloudX.SecurityMonitoring.Services.StorageDatabase;
using CloudX.SecurityMonitoring.UniversalRuleSupport;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
public class StorageDatabaseController : Controller
{
    private readonly IStorageDatabaseServices _service;

    public StorageDatabaseController(
        IStorageDatabaseServices service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> StoragePublicBlob()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStoragePublicBlobAsync(
                        entraTenantId);

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
                    "StoragePublicBlob",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
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
    public async Task<IActionResult> StorageSecureTransfer()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageSecureTransferAsync(
                        entraTenantId);

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
                    "StorageSecureTransfer",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> StorageSharedKeyAccess()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageSharedKeyAccessAsync(
                        entraTenantId);

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
                    "StorageSharedKeyAccess",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> SqlFirewall()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlFirewallAsync(
                        entraTenantId);

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
                    "SqlFirewall",
                    "",
                    "",
                    "Microsoft.Sql/servers",
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
                    .CheckSqlEncryptionAsync(
                        entraTenantId);

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
                    "SqlEncryption",
                    "",
                    "",
                    "Microsoft.Sql/servers/databases",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> SqlPrivateEndpoint()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlPrivateEndpointAsync(
                        entraTenantId);

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
                    "SqlPrivateEndpoint",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult>
    StorageSharedAccessSignatureExpiry()
    {
        var entraTenantId = GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageSharedAccessSignatureExpiryAsync(
                        entraTenantId);

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
                    "StorageSharedAccessSignatureExpiry",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
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
                    "StorageDatabaseScan",
                    "",
                    "",
                    "",
                    "CloudX could not complete the storage and database security scan."));
        }
    }
}