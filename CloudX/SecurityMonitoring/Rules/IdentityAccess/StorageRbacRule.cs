
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.IdentityAccess;

public sealed class StorageRbacRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageRbacRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckStorageRbacAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Storage/storageAccounts",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The Storage Account resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "?api-version=2023-05-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve Storage Account configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        bool? sharedKeyAccessAllowed = null;

        if (root.TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty(
                "allowSharedKeyAccess", out var sharedKeyProperty) &&
            (sharedKeyProperty.ValueKind == JsonValueKind.True ||
             sharedKeyProperty.ValueKind == JsonValueKind.False))
        {
            sharedKeyAccessAllowed = sharedKeyProperty.GetBoolean();
        }

        if (sharedKeyAccessAllowed == false)
        {
            return null;
        }

        if (sharedKeyAccessAllowed is null)
        {
            throw new InvalidOperationException(
                "The Storage Account response did not contain a valid " +
                "allowSharedKeyAccess property.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "IdentityAccess",
            Rule = "StorageRbac",
            Severity = "High",
            Title = "Storage Account allows shared key access",
            Description =
                "The Azure Storage Account permits shared key authentication, " +
                "allowing access without Microsoft Entra ID-based authorization.",
            Recommendation =
                "Disable shared key access and use Microsoft Entra ID with " +
                "Azure RBAC for Storage authorization.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
