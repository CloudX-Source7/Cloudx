
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Encryption;

public sealed class StorageCustomerManagedKeyRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageCustomerManagedKeyRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckStorageCustomerManagedKeyAsync(
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
                $"Failed to retrieve Storage Account encryption configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        var keySource =
            root.TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty("encryption", out var encryption) &&
            encryption.TryGetProperty("keySource", out var keySourceElement) &&
            keySourceElement.ValueKind == JsonValueKind.String
                ? keySourceElement.GetString()
                : null;

        // Customer-managed key configured.
        if (string.Equals(
                keySource,
                "Microsoft.Keyvault",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Encryption",
            Rule = "StorageCustomerManagedKey",
            Severity = "High",
            Title = "Storage Account is not using a customer-managed encryption key",
            Description =
                $"The Azure Storage Account '{resource.Name}' is not configured " +
                "to use a customer-managed encryption key.",
            Recommendation =
                "Configure a customer-managed key stored in Azure Key Vault " +
                "or Azure Key Vault Managed HSM when required by your security policy.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
