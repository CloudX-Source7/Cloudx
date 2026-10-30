
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppManagedIdentityRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppManagedIdentityRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppManagedIdentityAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Web/sites",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The Web App resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "?api-version=2024-04-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve Web App '{resource.Name}'. " +
                $"HTTP {(int)response.StatusCode}: {body}",
                null,
                response.StatusCode);
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        if (!document.RootElement.TryGetProperty(
                "identity", out var identity) ||
            identity.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "The Web App response does not contain a valid identity configuration.");
        }

        var systemAssigned = false;

        if (identity.TryGetProperty(
                "principalId", out var principalId) &&
            principalId.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(principalId.GetString()))
        {
            systemAssigned = true;
        }

        var userAssigned = false;

        if (identity.TryGetProperty(
                "userAssignedIdentities", out var userIdentities) &&
            userIdentities.ValueKind == JsonValueKind.Object)
        {
            userAssigned = userIdentities.EnumerateObject().Any();
        }

        if (systemAssigned || userAssigned)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "WebAppManagedIdentity",
            Severity = "High",
            Title = "Managed Identity is not enabled",
            Description =
                "The Azure Web App does not have a managed identity configured.",
            Recommendation =
                "Enable a system-assigned or user-assigned managed identity for the Azure Web App.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
