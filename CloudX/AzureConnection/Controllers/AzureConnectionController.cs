using Azure;
using Azure.Core;
using Azure.ResourceManager;
using CloudX.AzureConnection.DTOs;
using CloudX.AzureConnection.Services;
using CloudX.AzureDiscovery.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace CloudX.AzureConnection.Controllers;

[Authorize(AuthenticationSchemes = "CloudXLocal")]
[Route("AzureConnection")]
public sealed class AzureConnectionController : Controller
{
    private const string LocalScheme = "CloudXLocal";
    private const string AzureCookieScheme = "AzureCookies";

    private readonly IAzureConnectionService _service;
    private readonly ArmClient _armClient;
    private readonly IAzureDiscoveryService _discoveryService;
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public AzureConnectionController(
        IAzureConnectionService service,
        ArmClient armClient,
        IAzureDiscoveryService discoveryService,
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _service = service;
        _armClient = armClient;
        _discoveryService = discoveryService;
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    // Displays the Azure connection page.
    [HttpGet("")]
    [HttpGet("Index")]
    public async Task<IActionResult> Index()
    {
        var localResult =
            await HttpContext.AuthenticateAsync(LocalScheme);

        if (!localResult.Succeeded ||
            localResult.Principal is null)
        {
            return Challenge(LocalScheme);
        }

        var azureResult =
            await HttpContext.AuthenticateAsync(AzureCookieScheme);

        var model = new AzureConnectionPageViewModel
        {
            IsAzureAuthorized =
                azureResult.Succeeded &&
                azureResult.Principal is not null
        };

        if (model.IsAzureAuthorized)
        {
            model.TenantId = GetTenantId(
                azureResult.Principal!);

            var userId = GetLocalUserId(
                localResult.Principal);

            if (userId is null)
                return Forbid(LocalScheme);

            model.Connections =
                await _service.GetConnectionsAsync(userId.Value);
        }

        return View(
            "~/Views/AzureConnection/Index.cshtml",
            model);
    }

    // Starts Microsoft authorization.
    [HttpGet("Connect")]
    public IActionResult Connect()
    {
        var properties = new AuthenticationProperties
        {
            RedirectUri =
                Url.Action(nameof(Index), "AzureConnection")
                ?? "/AzureConnection"
        };

        return Challenge(
            properties,
            OpenIdConnectDefaults.AuthenticationScheme);
    }

    // Validates and saves a subscription.
    [HttpPost("AddSubscription")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> AddSubscription(string subscriptionId)
    {
        var localResult =
            await HttpContext.AuthenticateAsync(LocalScheme);
       
        if (!localResult.Succeeded || localResult.Principal is null)
            return Challenge(LocalScheme);

        var azureResult =
            await HttpContext.AuthenticateAsync(AzureCookieScheme);

        if (!azureResult.Succeeded || azureResult.Principal is null)
        {
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri =
                        Url.Action(nameof(Index), "AzureConnection")
                        ?? "/AzureConnection"
                },
                OpenIdConnectDefaults.AuthenticationScheme);
        }

        if (string.IsNullOrWhiteSpace(subscriptionId) ||
            !Guid.TryParse(subscriptionId.Trim(), out var subscriptionGuid))
        {
            TempData["ErrorMessage"] = "Enter a valid subscription ID.";
            return RedirectToAction(nameof(Index));
        }

        var userId = GetLocalUserId(localResult.Principal);
        var tenantId = GetTenantId(azureResult.Principal);

        if (userId is null)
            return Forbid(LocalScheme);

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            TempData["ErrorMessage"] =
                "Could not determine the authenticated Azure tenant.";

            return RedirectToAction(nameof(Index));
        }

        try
        {
            // Acquire a token explicitly for the Azure-authenticated user.
            var accessToken =
                await _tokenAcquisition.GetAccessTokenForUserAsync(
                    new[] { "https://management.azure.com/user_impersonation" },
                    authenticationScheme:
                        OpenIdConnectDefaults.AuthenticationScheme,
                    tenantId: tenantId,
                    user: azureResult.Principal);

            var requestUrl =
                $"https://management.azure.com/subscriptions/{subscriptionGuid:D}" +
                "?api-version=2022-12-01";

            using var request =
                new HttpRequestMessage(HttpMethod.Get, requestUrl);

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var httpClient = _httpClientFactory.CreateClient();

            using var httpResponse = await httpClient.SendAsync(request);

            if (!httpResponse.IsSuccessStatusCode)
            {
                TempData["ErrorMessage"] =
                    $"Azure subscription validation failed " +
                    $"(HTTP {(int)httpResponse.StatusCode}). " +
                    "Check the subscription ID, Azure permissions, and consent.";

                return RedirectToAction(nameof(Index));
            }

            using var json = JsonDocument.Parse(
                await httpResponse.Content.ReadAsStringAsync());

            var root = json.RootElement;

            var verifiedId =
                root.TryGetProperty("subscriptionId", out var idElement)
                    ? idElement.GetString()
                    : null;

            var verifiedTenantId =
                root.TryGetProperty("tenantId", out var tenantElement)
                    ? tenantElement.GetString()
                    : null;

            if (!Guid.TryParse(verifiedId, out var verifiedGuid) ||
                verifiedGuid != subscriptionGuid)
            {
                TempData["ErrorMessage"] =
                    "Azure could not verify that subscription.";

                return RedirectToAction(nameof(Index));
            }

            if (!string.Equals(
                    verifiedTenantId,
                    tenantId,
                    StringComparison.OrdinalIgnoreCase))
            {
                TempData["ErrorMessage"] =
                    "The subscription does not belong to the authenticated Azure tenant.";

                return RedirectToAction(nameof(Index));
            }

            var customerName =
                azureResult.Principal.FindFirst("name")?.Value
                ?? azureResult.Principal.FindFirst("preferred_username")?.Value
                ?? "Azure Customer";

            await _service.ConnectAsync(
                userId.Value,
                tenantId,
                customerName,
                verifiedGuid.ToString("D"));

            TempData["SuccessMessage"] =
                "Subscription connected successfully.";
        }
        catch (MicrosoftIdentityWebChallengeUserException)
        {
            TempData["ErrorMessage"] =
                "Microsoft requires you to sign in again or grant consent. " +
                "Reconnect your Azure account and retry.";
        }
        catch (HttpRequestException)
        {
            TempData["ErrorMessage"] =
                "Could not reach Azure Resource Manager. Check your network connection.";
        }
        catch (JsonException)
        {
            TempData["ErrorMessage"] =
                "Azure returned an unexpected response while validating the subscription.";
        }

        return RedirectToAction(nameof(Index));
    }

    // Validates the saved subscription and discovers its resources.
    [HttpPost("SelectSubscription")]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SelectSubscription(
        string subscriptionId)
    {
        var localResult =
            await HttpContext.AuthenticateAsync(LocalScheme);

        if (!localResult.Succeeded ||
            localResult.Principal is null)
        {
            return Challenge(LocalScheme);
        }

        var azureResult =
            await HttpContext.AuthenticateAsync(AzureCookieScheme);

        if (!azureResult.Succeeded ||
            azureResult.Principal is null)
        {
            return Challenge(
                new AuthenticationProperties
                {
                    RedirectUri =
                        Url.Action(nameof(Index), "AzureConnection")
                        ?? "/AzureConnection"
                },
                OpenIdConnectDefaults.AuthenticationScheme);
        }

        var userId = GetLocalUserId(
            localResult.Principal);

        if (userId is null)
            return Forbid(LocalScheme);

        var tenantId = GetTenantId(
            azureResult.Principal);

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            TempData["ErrorMessage"] =
                "Could not determine the authenticated Azure tenant.";

            return RedirectToAction(nameof(Index));
        }

        if (string.IsNullOrWhiteSpace(subscriptionId) ||
            !Guid.TryParse(
                subscriptionId.Trim(),
                out var subscriptionGuid))
        {
            TempData["ErrorMessage"] =
                "Select a valid subscription.";

            return RedirectToAction(nameof(Index));
        }

        var normalizedSubscriptionId =
            subscriptionGuid.ToString("D");

        var connections =
            await _service.GetConnectionsAsync(userId.Value);

        var isSaved = connections.Any(c =>
            string.Equals(
                c.SubscriptionId,
                normalizedSubscriptionId,
                StringComparison.OrdinalIgnoreCase));

        if (!isSaved)
        {
            TempData["ErrorMessage"] =
                "That subscription is not saved for your CloudX account.";

            return RedirectToAction(nameof(Index));
        }

        try
        {
            var resources =
                await _discoveryService.DiscoverResourcesAsync(
                    tenantId,
                    normalizedSubscriptionId);

            TempData["SuccessMessage"] =
                $"Subscription selected successfully. " +
                $"Azure Discovery found {resources.Count} resources.";
        }
        catch (RequestFailedException ex)
            when (ex.Status is 400 or 403 or 404)
        {
            TempData["ErrorMessage"] =
                "Azure Discovery failed. Check subscription access and Azure permissions.";
        }
        catch (UnauthorizedAccessException)
        {
            TempData["ErrorMessage"] =
                "The selected subscription does not belong to the authenticated Azure tenant.";
        }
        catch (ArgumentException)
        {
            TempData["ErrorMessage"] =
                "The tenant ID or subscription ID is invalid.";
        }

        return RedirectToAction(nameof(Index));
    }

    private static int? GetLocalUserId(
        ClaimsPrincipal principal)
    {
        var value =
            principal.FindFirst(
                ClaimTypes.NameIdentifier)?.Value;

        return int.TryParse(value, out var userId)
            ? userId
            : null;
    }

    private static string? GetTenantId(
        ClaimsPrincipal principal)
    {
        return principal.FindFirst("tid")?.Value
            ?? principal.FindFirst(
                "http://schemas.microsoft.com/identity/claims/tenantid")
                ?.Value;
    }
    [HttpGet("SubscriptionSelector")]
    public async Task<IActionResult> SubscriptionSelector()
    {
        var localResult =
            await HttpContext.AuthenticateAsync(LocalScheme);

        if (!localResult.Succeeded ||
            localResult.Principal is null)
        {
            return Challenge(LocalScheme);
        }

        var azureResult =
            await HttpContext.AuthenticateAsync(AzureCookieScheme);

        if (!azureResult.Succeeded ||
            azureResult.Principal is null)
        {
            return RedirectToAction(nameof(Connect));
        }

        var userId = GetLocalUserId(localResult.Principal);

        if (userId is null)
            return Forbid(LocalScheme);

        var model = new AzureConnectionPageViewModel
        {
            IsAzureAuthorized = true,
            TenantId = GetTenantId(azureResult.Principal),
            Connections = await _service.GetConnectionsAsync(userId.Value)
        };

        return View(
            "~/Views/AzureConnection/SubscriptionSelector.cshtml",
            model);
    }
}
