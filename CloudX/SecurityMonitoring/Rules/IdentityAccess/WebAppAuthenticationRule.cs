
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.IdentityAccess;

public sealed class WebAppAuthenticationRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppAuthenticationRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppAuthenticationAsync(
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
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "/config/authsettingsV2" +
            "?api-version=2022-03-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve Web App authentication settings. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty("platform", out var platform) ||
            !platform.TryGetProperty("enabled", out var enabledProperty) ||
            (enabledProperty.ValueKind != JsonValueKind.True &&
             enabledProperty.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "The Web App response did not contain a valid " +
                "platform.enabled property.");
        }

        var authenticationEnabled = enabledProperty.GetBoolean();

        if (!properties.TryGetProperty(
                "globalValidation", out var globalValidation) ||
            !globalValidation.TryGetProperty(
                "requireAuthentication", out var requiredProperty) ||
            (requiredProperty.ValueKind != JsonValueKind.True &&
             requiredProperty.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "The Web App response did not contain a valid " +
                "globalValidation.requireAuthentication property.");
        }

        var authenticationRequired = requiredProperty.GetBoolean();

        if (authenticationEnabled && authenticationRequired)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "IdentityAccess",
            Rule = "WebAppAuthentication",
            Severity = "High",
            Title = "Web App authentication is not properly configured",
            Description =
                "The Azure Web App does not have authentication enabled " +
                "and required for incoming requests.",
            Recommendation =
                "Enable App Service Authentication and require authentication " +
                "for incoming requests.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
