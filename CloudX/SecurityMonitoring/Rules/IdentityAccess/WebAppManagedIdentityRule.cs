
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.IdentityAccess;

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
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "?api-version=2024-04-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve Web App managed identity configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("identity", out var identity) ||
            identity.ValueKind == JsonValueKind.Null)
        {
            return CreateFinding(resource);
        }

        var systemAssignedEnabled =
            identity.TryGetProperty("principalId", out var principalId) &&
            principalId.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(principalId.GetString());

        var userAssignedEnabled =
            identity.TryGetProperty(
                "userAssignedIdentities", out var userAssignedIdentities) &&
            userAssignedIdentities.ValueKind == JsonValueKind.Object &&
            userAssignedIdentities.EnumerateObject().Any();

        if (systemAssignedEnabled || userAssignedEnabled)
        {
            return null;
        }

        return CreateFinding(resource);
    }

    private static SecurityFindingDto CreateFinding(ResourceDto resource)
    {
        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "IdentityAccess",
            Rule = "WebAppManagedIdentity",
            Severity = "High",
            Title = "Web App does not have a managed identity enabled",
            Description =
                "The Azure Web App does not have a system-assigned or " +
                "user-assigned managed identity configured.",
            Recommendation =
                "Enable a managed identity for the Web App and use it for " +
                "Azure resource authentication instead of storing credentials.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
