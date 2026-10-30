    using CloudX.SecurityMonitoring.Services.PublicExposure;
    using CloudX.SecurityMonitoring.UniversalRuleSupport;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using System.Security.Claims;

    namespace CloudX.SecurityMonitoring.Controllers;

    [Authorize(AuthenticationSchemes = "CloudXLocal,AzureCookies")]
    public class PublicExposureController : Controller
    {
        private readonly IPublicExposureService _service;

        public PublicExposureController(
            IPublicExposureService service)
        {
            _service = service;
        }

        [HttpGet]
        public async Task<IActionResult> WebAppPublicAccess()
        {
            var entraTenantId = GetTenantId();

            if (string.IsNullOrWhiteSpace(entraTenantId))
                return Unauthorized();

            try
            {
                var findings =
                    await _service
                        .CheckWebAppPublicAccessAsync(entraTenantId);

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
                        "WebAppPublicAccess",
                        "",
                        "",
                        "Microsoft.Web/sites",
                        "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
            }
        }

        [HttpGet]
        public async Task<IActionResult> SqlPublicAccess()
        {
            var entraTenantId = GetTenantId();

            if (string.IsNullOrWhiteSpace(entraTenantId))
                return Unauthorized();

            try
            {
                var findings =
                    await _service
                        .CheckSqlPublicAccessAsync(entraTenantId);

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
                        "SqlPublicAccess",
                        "",
                        "",
                        "Microsoft.Sql/servers",
                        "CloudX could not evaluate this security rule because it does not have the required Azure permissions."));
            }
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
                        .CheckStoragePublicBlobAsync(entraTenantId);

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

        [HttpGet]
        public async Task<IActionResult> KeyVaultPublicNetwork()
        {
            var entraTenantId = GetTenantId();

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
                        "PublicExposureScan",
                        "",
                        "",
                        "",
                        "CloudX could not complete the public exposure security scan."));
            }
        }
    }