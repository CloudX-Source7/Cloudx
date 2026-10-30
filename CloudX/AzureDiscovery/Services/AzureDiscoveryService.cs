
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace CloudX.AzureDiscovery.Services;

public sealed class AzureDiscoveryService : IAzureDiscoveryService
{
    private const string AzureCookieScheme = "AzureCookies";

    private const string ManagementScope =
        "https://management.azure.com/user_impersonation";

    private const string SubscriptionsApiVersion = "2022-12-01";
    private const string ResourcesApiVersion = "2021-04-01";

    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IHttpClientFactory _httpClientFactory;

    public AzureDiscoveryService(
        ITokenAcquisition tokenAcquisition,
        IHttpContextAccessor httpContextAccessor,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpContextAccessor = httpContextAccessor;
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Discovers resources across accessible subscriptions
    /// belonging to the specified Entra tenant.
    /// </summary>
    public async Task<IReadOnlyList<ResourceDto>> DiscoverResourcesAsync(
        string entraTenantId)
    {
        if (string.IsNullOrWhiteSpace(entraTenantId))
        {
            throw new ArgumentException(
                "Entra tenant ID is required.",
                nameof(entraTenantId));
        }

        var subscriptions = await GetSubscriptionsAsync(entraTenantId);
        var results = new List<ResourceDto>();

        foreach (var subscription in subscriptions)
        {
            var subscriptionId = subscription.SubscriptionId;

            if (string.IsNullOrWhiteSpace(subscriptionId))
                continue;

            var resources = await DiscoverSubscriptionAsync(subscriptionId);
            results.AddRange(resources);
        }

        return results;
    }

    /// <summary>
    /// Discovers resources from one subscription after checking
    /// that it belongs to the specified Entra tenant.
    /// </summary>
    public async Task<IReadOnlyList<ResourceDto>> DiscoverResourcesAsync(
        string entraTenantId,
        string subscriptionId)
    {
        if (string.IsNullOrWhiteSpace(entraTenantId))
        {
            throw new ArgumentException(
                "Entra tenant ID is required.",
                nameof(entraTenantId));
        }

        if (!Guid.TryParse(subscriptionId, out var subscriptionGuid))
        {
            throw new ArgumentException(
                "A valid subscription ID is required.",
                nameof(subscriptionId));
        }

        var normalizedSubscriptionId = subscriptionGuid.ToString("D");

        var subscriptions = await GetSubscriptionsAsync(entraTenantId);

        var matchingSubscription = subscriptions.FirstOrDefault(s =>
            string.Equals(
                s.SubscriptionId,
                normalizedSubscriptionId,
                StringComparison.OrdinalIgnoreCase));

        if (matchingSubscription is null)
        {
            throw new UnauthorizedAccessException(
                "The subscription is not accessible in the authenticated Azure tenant.");
        }

        if (!string.Equals(
                matchingSubscription.TenantId,
                entraTenantId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                "The subscription does not belong to the specified tenant.");
        }

        return await DiscoverSubscriptionAsync(normalizedSubscriptionId);
    }

    private async Task<List<SubscriptionInfo>> GetSubscriptionsAsync(
        string tenantId)
    {
        var client = _httpClientFactory.CreateClient();
        var token = await GetAzureAccessTokenAsync(tenantId);

        var url =
            $"https://management.azure.com/subscriptions" +
            $"?api-version={SubscriptionsApiVersion}";

        var subscriptions = new List<SubscriptionInfo>();

        while (!string.IsNullOrWhiteSpace(url))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            using var response = await client.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Azure subscription discovery failed with HTTP " +
                    $"{(int)response.StatusCode}: {body}",
                    null,
                    response.StatusCode);
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            if (root.TryGetProperty("value", out var values) &&
                values.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in values.EnumerateArray())
                {
                    var id = ReadString(item, "subscriptionId");
                    var subscriptionTenantId = ReadString(item, "tenantId");

                    if (string.IsNullOrWhiteSpace(id) ||
                        !Guid.TryParse(id, out _))
                    {
                        continue;
                    }

                    if (!string.Equals(
                            subscriptionTenantId,
                            tenantId,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    subscriptions.Add(new SubscriptionInfo(
                        Guid.Parse(id).ToString("D"),
                        subscriptionTenantId ?? string.Empty));
                }
            }

            url = root.TryGetProperty("nextLink", out var nextLink)
                  && nextLink.ValueKind == JsonValueKind.String
                ? nextLink.GetString() ?? string.Empty
                : string.Empty;
        }

        return subscriptions;
    }

    private async Task<IReadOnlyList<ResourceDto>> DiscoverSubscriptionAsync(
        string subscriptionId)
    {
        var client = _httpClientFactory.CreateClient();
        var token = await GetAzureAccessTokenAsync(null);
        var results = new List<ResourceDto>();

        results.Add(new ResourceDto
        {
            Id = $"/subscriptions/{subscriptionId}",
            Name = subscriptionId,
            Type = "Microsoft.Resources/subscriptions"
        });

        var url =
            $"https://management.azure.com/subscriptions/{subscriptionId}" +
            $"/resources?api-version={ResourcesApiVersion}";

        while (!string.IsNullOrWhiteSpace(url))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            using var response = await client.SendAsync(request);
            var body = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Azure resource discovery failed for subscription " +
                    $"{subscriptionId} with HTTP {(int)response.StatusCode}: {body}",
                    null,
                    response.StatusCode);
            }

            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;

            if (root.TryGetProperty("value", out var values) &&
                values.ValueKind == JsonValueKind.Array)
            {
                foreach (var resource in values.EnumerateArray())
                {
                    var id = ReadString(resource, "id");
                    var name = ReadString(resource, "name");
                    var type = ReadString(resource, "type");

                    if (string.IsNullOrWhiteSpace(id))
                        continue;

                    results.Add(new ResourceDto
                    {
                        Id = id,
                        Name = name ?? id,
                        Type = type ?? "Unknown"
                    });
                }
            }

            url = root.TryGetProperty("nextLink", out var nextLink)
                  && nextLink.ValueKind == JsonValueKind.String
                ? nextLink.GetString() ?? string.Empty
                : string.Empty;
        }

        return results;
    }

    private async Task<string> GetAzureAccessTokenAsync(string? tenantId)
    {
        var context = _httpContextAccessor.HttpContext
            ?? throw new InvalidOperationException(
                "Azure discovery requires an active HTTP request.");

        var azureResult =
            await context.AuthenticateAsync(AzureCookieScheme);

        if (!azureResult.Succeeded || azureResult.Principal is null)
        {
            throw new UnauthorizedAccessException(
                "Connect your Microsoft Azure account before discovering resources.");
        }

        var authenticatedTenantId =
            azureResult.Principal.FindFirst("tid")?.Value
            ?? azureResult.Principal.FindFirst(
                "http://schemas.microsoft.com/identity/claims/tenantid")?.Value;

        if (string.IsNullOrWhiteSpace(authenticatedTenantId))
        {
            throw new UnauthorizedAccessException(
                "The Azure sign-in session does not contain a tenant ID.");
        }

        if (!string.IsNullOrWhiteSpace(tenantId) &&
            !string.Equals(
                authenticatedTenantId,
                tenantId,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                "The authenticated Azure account does not match the requested tenant.");
        }

        return await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { ManagementScope },
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme,
            tenantId: authenticatedTenantId,
            user: azureResult.Principal);
    }

    private static string? ReadString(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private sealed record SubscriptionInfo(
        string SubscriptionId,
        string TenantId);
}
