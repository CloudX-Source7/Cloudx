
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.NetworkFirewall;

public sealed class StorageNetworkRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageNetworkRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckStorageNetworkAsync(
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
                $"Failed to retrieve Storage Account network configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty(
                "publicNetworkAccess", out var publicAccessProperty) ||
            publicAccessProperty.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The Storage Account response did not contain a valid " +
                "publicNetworkAccess property.");
        }

        var publicNetworkAccess = publicAccessProperty.GetString();

        if (!string.Equals(
                publicNetworkAccess,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "NetworkFirewall",
            Rule = "StorageNetwork",
            Severity = "High",
            Title = "Storage Account allows public network access",
            Description =
                $"The Azure Storage Account '{resource.Name}' allows access " +
                "through the public network.",
            Recommendation =
                "Disable public network access and use private endpoints " +
                "or trusted network access instead.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
