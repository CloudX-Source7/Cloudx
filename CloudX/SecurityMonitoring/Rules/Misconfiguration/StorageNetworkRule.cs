
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

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
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "?api-version=2023-05-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve Storage Account '{resource.Name}'. " +
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
                "publicNetworkAccess", out var publicAccess) ||
            publicAccess.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The Storage Account response does not contain a valid " +
                "properties.publicNetworkAccess value.");
        }

        var access = publicAccess.GetString();

        if (string.Equals(
                access, "Disabled",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                access, "SecuredByPerimeter",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.Equals(
                access, "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"Storage Account public network access has an " +
                $"unrecognized value: '{access}'.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "StorageNetwork",
            Severity = "High",
            Title = "Storage Account allows public network access",
            Description =
                "The Azure Storage Account allows access through its public network endpoint.",
            Recommendation =
                "Disable public network access and use private endpoints or other restricted network access where possible.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
