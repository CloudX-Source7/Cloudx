
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Encryption;

public sealed class StorageEncryptionRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageEncryptionRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckStorageEncryptionAsync(
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

        var infrastructureEncryptionEnabled =
            root.TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty(
                "encryption", out var encryption) &&
            encryption.TryGetProperty(
                "requireInfrastructureEncryption", out var infrastructure) &&
            infrastructure.ValueKind == JsonValueKind.True;

        if (infrastructureEncryptionEnabled)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Encryption",
            Rule = "StorageEncryption",
            Severity = "Medium",
            Title = "Storage infrastructure encryption is not enabled",
            Description =
                $"The Azure Storage Account '{resource.Name}' does not have " +
                "the additional infrastructure-level encryption layer enabled.",
            Recommendation =
                "Enable infrastructure encryption when double encryption is " +
                "required by your security policy or compliance requirements.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
