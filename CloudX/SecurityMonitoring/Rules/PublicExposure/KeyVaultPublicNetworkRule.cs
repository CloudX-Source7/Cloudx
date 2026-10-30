
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.PublicExposure;

public sealed class KeyVaultPublicNetworkRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public KeyVaultPublicNetworkRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckKeyVaultPublicNetworkAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.KeyVault/vaults",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The Key Vault resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "?api-version=2023-07-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve Key Vault network configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty(
                "publicNetworkAccess", out var publicNetworkProperty) ||
            publicNetworkProperty.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The Key Vault response did not contain a valid " +
                "publicNetworkAccess property.");
        }

        var publicNetworkAccess = publicNetworkProperty.GetString();

        if (string.Equals(
                publicNetworkAccess,
                "Disabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "PublicExposure",
            Rule = "KeyVaultPublicNetwork",
            Severity = "High",
            Title = "Key Vault allows public network access",
            Description =
                "The Azure Key Vault allows access through its public " +
                "network endpoint.",
            Recommendation =
                "Disable public network access and use private connectivity " +
                "when public access is not required.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
