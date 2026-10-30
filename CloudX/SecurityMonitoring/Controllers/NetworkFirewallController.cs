using CloudX.SecurityMonitoring.Services.NetworkFirewall;
using CloudX.SecurityMonitoring.UniversalRuleSupport;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CloudX.SecurityMonitoring.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
public class NetworkFirewallController : Controller
{
    private readonly INetworkFirewallService _service;

    public NetworkFirewallController(
        INetworkFirewallService service)
    {
        _service = service;
    }

    [HttpGet]
    public async Task<IActionResult> SqlFirewall()
    {
        var entraTenantId =
            GetTenantId();

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

    private string? GetTenantId()
    {
        return User.FindFirstValue("tid")
            ?? User.FindFirstValue(
                "http://schemas.microsoft.com/identity/claims/tenantid");
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
                    .CheckSqlPublicNetworkAsync(
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
                    "SqlPublicNetwork",
                    "",
                    "",
                    "Microsoft.Sql/servers",
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
                    .CheckStorageNetworkAsync(
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
                    "StorageNetwork",
                    "",
                    "",
                    "Microsoft.Storage/storageAccounts",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> KeyVaultFirewall()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckKeyVaultFirewallAsync(
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
                    "KeyVaultFirewall",
                    "",
                    "",
                    "Microsoft.KeyVault/vaults",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> NsgOpenInternet()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckNsgOpenInternetAsync(
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
                    "NsgOpenInternet",
                    "",
                    "",
                    "Microsoft.Network/networkSecurityGroups",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> NsgBroadInbound()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckNsgBroadInboundAsync(
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
                    "NsgBroadInbound",
                    "",
                    "",
                    "Microsoft.Network/networkSecurityGroups",
                    "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
        }
    }
    [HttpGet]
    public async Task<IActionResult> SubnetMissingNsg()
    {
        var entraTenantId =
            GetTenantId();

        if (string.IsNullOrWhiteSpace(entraTenantId))
            return Unauthorized();

        try
        {
            var findings =
                await _service
                    .CheckSubnetMissingNsgAsync(
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
                    "SubnetMissingNsg",
                    "",
                    "",
                    "Microsoft.Network/virtualNetworks/subnets",
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
                    "NetworkFirewallScan",
                    "",
                    "",
                    "",
                    "CloudX could not complete the network and firewall security scan."));
        }
    }
}