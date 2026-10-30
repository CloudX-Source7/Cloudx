
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Encryption;

public sealed class KeyVaultKeyProtectionRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public KeyVaultKeyProtectionRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckKeyVaultKeyProtectionAsync(
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

        var armUrl =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "?api-version=2023-07-01";

        using var armRequest =
            new HttpRequestMessage(HttpMethod.Get, armUrl);

        armRequest.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var armResponse = await client.SendAsync(armRequest);
        var armBody = await armResponse.Content.ReadAsStringAsync();

        if (!armResponse.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve Key Vault configuration. " +
                $"HTTP {(int)armResponse.StatusCode}: {armBody}");
        }

        using var armDocument = JsonDocument.Parse(armBody);
        var armRoot = armDocument.RootElement;

        var vaultUri =
            armRoot.TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty("vaultUri", out var vaultUriElement) &&
            vaultUriElement.ValueKind == JsonValueKind.String
                ? vaultUriElement.GetString()
                : null;

        if (string.IsNullOrWhiteSpace(vaultUri))
        {
            throw new InvalidOperationException(
                "The Key Vault response did not contain a vault URI.");
        }

        // Key Vault data-plane API requires a Key Vault-scoped token.
        var keyVaultToken =
            await _tokenAcquisition.GetAccessTokenForUserAsync(
                new[] { $"{vaultUri.TrimEnd('/')}/.default" },
                authenticationScheme:
                    OpenIdConnectDefaults.AuthenticationScheme);

        var keyUrl = $"{vaultUri.TrimEnd('/')}/keys?api-version=7.4";

        while (!string.IsNullOrWhiteSpace(keyUrl))
        {
            using var keysRequest =
                new HttpRequestMessage(HttpMethod.Get, keyUrl);

            keysRequest.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", keyVaultToken);

            using var keysResponse = await client.SendAsync(keysRequest);
            var keysBody = await keysResponse.Content.ReadAsStringAsync();

            if (!keysResponse.IsSuccessStatusCode)
            {
                throw new HttpRequestException(
                    $"Failed to enumerate Key Vault keys. " +
                    $"HTTP {(int)keysResponse.StatusCode}: {keysBody}");
            }

            using var keysDocument = JsonDocument.Parse(keysBody);
            var keysRoot = keysDocument.RootElement;

            if (keysRoot.TryGetProperty("value", out var values) &&
                values.ValueKind == JsonValueKind.Array)
            {
                foreach (var keyProperties in values.EnumerateArray())
                {
                    var keyId =
                        keyProperties.TryGetProperty("kid", out var kidElement)
                            ? kidElement.GetString()
                            : null;

                    var keyName = GetKeyName(keyId);

                    if (string.IsNullOrWhiteSpace(keyName))
                    {
                        continue;
                    }

                    // Fetch the key metadata to read its key type.
                    var keyDetailUrl =
                        $"{vaultUri.TrimEnd('/')}/keys/{Uri.EscapeDataString(keyName)}" +
                        "?api-version=7.4";

                    using var detailRequest =
                        new HttpRequestMessage(HttpMethod.Get, keyDetailUrl);

                    detailRequest.Headers.Authorization =
                        new AuthenticationHeaderValue("Bearer", keyVaultToken);

                    using var detailResponse =
                        await client.SendAsync(detailRequest);

                    var detailBody =
                        await detailResponse.Content.ReadAsStringAsync();

                    if (!detailResponse.IsSuccessStatusCode)
                    {
                        throw new HttpRequestException(
                            $"Failed to retrieve metadata for Key Vault key " +
                            $"'{keyName}'. HTTP {(int)detailResponse.StatusCode}: {detailBody}");
                    }

                    using var detailDocument = JsonDocument.Parse(detailBody);
                    var detailRoot = detailDocument.RootElement;

                    var keyType =
                        detailRoot.TryGetProperty("key", out var keyObject) &&
                        keyObject.TryGetProperty("kty", out var typeElement)
                            ? typeElement.GetString()
                            : null;

                    var isHsmProtected =
                        string.Equals(keyType, "RSA-HSM",
                            StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(keyType, "EC-HSM",
                            StringComparison.OrdinalIgnoreCase) ||
                        string.Equals(keyType, "oct-HSM",
                            StringComparison.OrdinalIgnoreCase);

                    if (!isHsmProtected)
                    {
                        return new SecurityFindingDto
                        {
                            ResourceId = resource.Id,
                            ResourceName = resource.Name,
                            ResourceType = resource.Type,
                            Category = "Encryption",
                            Rule = "KeyVaultKeyProtection",
                            Severity = "Medium",
                            Title = "Key Vault contains a software-protected key",
                            Description =
                                $"The Azure Key Vault key '{keyName}' is not HSM-protected. " +
                                $"The reported key type is '{keyType ?? "unknown"}'.",
                            Recommendation =
                                "Use an HSM-backed key when hardware-backed key protection " +
                                "is required by your security policy.",
                            DetectedAt = DateTime.UtcNow
                        };
                    }
                }
            }

            keyUrl =
                keysRoot.TryGetProperty("nextLink", out var nextLink) &&
                nextLink.ValueKind == JsonValueKind.String
                    ? nextLink.GetString() ?? string.Empty
                    : string.Empty;
        }

        return null;
    }

    private static string? GetKeyName(string? keyId)
    {
        if (string.IsNullOrWhiteSpace(keyId))
        {
            return null;
        }

        var uri = new Uri(keyId);
        var segments = uri.AbsolutePath.Split(
            '/',
            StringSplitOptions.RemoveEmptyEntries);

        return segments.Length >= 2 &&
               string.Equals(segments[0], "keys",
                   StringComparison.OrdinalIgnoreCase)
            ? Uri.UnescapeDataString(segments[1])
            : null;
    }
}
