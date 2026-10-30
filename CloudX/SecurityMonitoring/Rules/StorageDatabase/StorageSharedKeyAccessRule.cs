
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.StorageDatabase;

public sealed class StorageSharedKeyAccessRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageSharedKeyAccessRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckStorageSharedKeyAccessAsync(
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
                $"Failed to retrieve Storage Account shared key settings. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty(
                "allowSharedKeyAccess", out var sharedKeyProperty) ||
            (sharedKeyProperty.ValueKind != JsonValueKind.True &&
             sharedKeyProperty.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "The Storage Account response did not contain a valid " +
                "allowSharedKeyAccess property.");
        }

        var allowSharedKeyAccess = sharedKeyProperty.GetBoolean();

        if (!allowSharedKeyAccess)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "StorageDatabase",
            Rule = "StorageSharedKeyAccess",
            Severity = "High",
            Title = "Storage Account allows shared key access",
            Description =
                $"The Azure Storage Account '{resource.Name}' allows " +
                "authentication using shared access keys.",
            Recommendation =
                "Disable shared key access and use Microsoft Entra ID " +
                "with role-based access control where possible.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
