
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.IdentityAccess;

public sealed class KeyVaultAccessPolicyRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public KeyVaultAccessPolicyRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckKeyVaultAccessPolicyAsync(
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
                $"Failed to retrieve Key Vault configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        bool? rbacEnabled = null;

        if (root.TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty(
                "enableRbacAuthorization", out var rbacProperty) &&
            (rbacProperty.ValueKind == JsonValueKind.True ||
             rbacProperty.ValueKind == JsonValueKind.False))
        {
            rbacEnabled = rbacProperty.GetBoolean();
        }

        // Azure RBAC is enabled, so the legacy access-policy model is not used.
        if (rbacEnabled == true)
        {
            return null;
        }

        // Do not treat an absent property as proof that access policies are enabled.
        if (rbacEnabled is null)
        {
            throw new InvalidOperationException(
                "The Key Vault response did not contain a valid " +
                "enableRbacAuthorization property.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "IdentityAccess",
            Rule = "KeyVaultAccessPolicy",
            Severity = "High",
            Title = "Key Vault uses access policies instead of Azure RBAC",
            Description =
                "The Azure Key Vault is using the legacy access-policy " +
                "authorization model for data-plane access.",
            Recommendation =
                "Evaluate migrating to Azure RBAC for Key Vault data-plane " +
                "authorization and assign only the roles required by each identity.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
