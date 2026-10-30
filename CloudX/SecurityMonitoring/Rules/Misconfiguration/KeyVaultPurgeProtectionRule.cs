
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class KeyVaultPurgeProtectionRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public KeyVaultPurgeProtectionRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckKeyVaultPurgeProtectionAsync(
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
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "?api-version=2023-07-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve Key Vault '{resource.Name}'. " +
                $"HTTP {(int)response.StatusCode}: {body}",
                null,
                response.StatusCode);
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        if (!document.RootElement.TryGetProperty(
                "properties", out var properties) ||
            !properties.TryGetProperty(
                "enablePurgeProtection", out var purgeProtection) ||
            purgeProtection.ValueKind is not (
                JsonValueKind.True or JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "The Key Vault response does not contain a valid " +
                "properties.enablePurgeProtection value.");
        }

        if (purgeProtection.GetBoolean())
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "KeyVaultPurgeProtection",
            Severity = "High",
            Title = "Key Vault purge protection is disabled",
            Description =
                "The Azure Key Vault does not have purge protection enabled.",
            Recommendation =
                "Enable purge protection to prevent permanent deletion of protected Key Vault data during the soft-delete retention period.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
