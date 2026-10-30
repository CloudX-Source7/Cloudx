using CloudX.SecurityMonitoring.Services;
using CloudX.SecurityMonitoring.UniversalRuleSupport;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
public class MisconfigurationController : Controller
{
    private readonly IMisconfigurationService _service;

    public MisconfigurationController(
        IMisconfigurationService service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> WebAppHttpsOnly()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppHttpsOnlyAsync(entraTenantId);

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
                    "WebAppHttpsOnly",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppAuthentication()
    {
        var entraTenantId =
            GetTenantId();

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
                    ex.Message));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppManagedIdentity()
    {
        var entraTenantId =
            GetTenantId();

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
    public async Task<IActionResult> WebAppRemoteDebugging()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppRemoteDebuggingAsync(entraTenantId);

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
                    "WebAppRemoteDebugging",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppBasicAuthentication()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppBasicAuthenticationAsync(entraTenantId);

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
                    "WebAppBasicAuthentication",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppCors()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppCorsAsync(entraTenantId);

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
                    "WebAppCors",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppFtpState()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppFtpStateAsync(entraTenantId);

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
                    "WebAppFtpState",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> WebAppLogging()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckWebAppLoggingAsync(entraTenantId);

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
                    "WebAppLogging",
                    "",
                    "",
                    "Microsoft.Web/sites",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlPublicNetwork()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlPublicNetworkAsync(entraTenantId);

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
                    "SqlPublicNetwork",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlFirewallRule()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlFirewallRuleAsync(entraTenantId);

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
                    "SqlFirewallRule",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> SqlTls()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSqlTlsAsync(entraTenantId);

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
                    "SqlTls",
                    "",
                    "",
                    "Microsoft.Sql/servers",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> StoragePublicAccess()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStoragePublicAccessAsync(entraTenantId);

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
                    "StoragePublicAccess",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> StorageSecureTransfer()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageSecureTransferAsync(entraTenantId);

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
    public async Task<IActionResult> StorageNetwork()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckStorageNetworkAsync(entraTenantId);

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
                    "StorageNetwork",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultPublicNetwork()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultPublicNetworkAsync(entraTenantId);

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
                    "KeyVaultPublicNetwork",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultSoftDelete()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultSoftDeleteAsync(entraTenantId);

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
                    "KeyVaultSoftDelete",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }

    [HttpGet]
    public async Task<IActionResult> KeyVaultPurgeProtection()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultPurgeProtectionAsync(entraTenantId);

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
                    "KeyVaultPurgeProtection",
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
    public async Task<IActionResult> ActivityLogAlertMissing()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckActivityLogAlertMissingAsync(entraTenantId);

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
                    "ActivityLogAlertMissing",
                    "",
                    "",
                    "Microsoft.Resources/subscriptions",
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
                    "MisconfigurationScan",
                    "",
                    "",
                    "",
                    "CloudX could not complete the misconfiguration security scan."));
        }
    }
}