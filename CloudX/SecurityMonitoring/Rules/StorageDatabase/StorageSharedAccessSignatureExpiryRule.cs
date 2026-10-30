
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.StorageDatabase;

public sealed class StorageSharedAccessSignatureExpiryRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public StorageSharedAccessSignatureExpiryRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?>
        CheckStorageSharedAccessSignatureExpiryAsync(
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
                $"Failed to retrieve Storage Account SAS policy. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties))
        {
            throw new InvalidOperationException(
                "The Storage Account response did not contain a properties object.");
        }

        if (!properties.TryGetProperty("sasPolicy", out var sasPolicy) ||
            sasPolicy.ValueKind == JsonValueKind.Null)
        {
            return CreateFinding(
                resource,
                "Storage Account has no SAS expiration policy",
                $"The Azure Storage Account '{resource.Name}' does not have " +
                "a SAS expiration policy configured.",
                "Configure a SAS expiration period and enforce the policy " +
                "using the Block expiration action.");
        }

        if (sasPolicy.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException(
                "The Storage Account sasPolicy property has an unexpected value.");
        }

        var expirationPeriod = GetString(sasPolicy, "sasExpirationPeriod");
        var expirationAction = GetString(sasPolicy, "expirationAction");

        if (string.IsNullOrWhiteSpace(expirationPeriod) ||
            !string.Equals(
                expirationAction,
                "Block",
                StringComparison.OrdinalIgnoreCase))
        {
            return CreateFinding(
                resource,
                "Storage Account SAS expiration policy is not enforced",
                $"The Azure Storage Account '{resource.Name}' does not enforce " +
                "a valid SAS expiration policy.",
                "Configure a reasonable SAS expiration period and set the " +
                "SAS expiration action to Block.");
        }

        if (!System.Xml.XmlConvert.ToTimeSpan(expirationPeriod).Ticks.Equals(
                System.Xml.XmlConvert.ToTimeSpan(expirationPeriod).Ticks))
        {
            throw new InvalidOperationException(
                "The SAS expiration period is invalid.");
        }

        return null;
    }

    private static string? GetString(
        JsonElement element,
        string propertyName)
    {
        return element.TryGetProperty(propertyName, out var property) &&
               property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;
    }

    private static SecurityFindingDto CreateFinding(
        ResourceDto resource,
        string title,
        string description,
        string recommendation)
    {
        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "StorageDatabase",
            Rule = "StorageSharedAccessSignatureExpiry",
            Severity = "High",
            Title = title,
            Description = description,
            Recommendation = recommendation,
            DetectedAt = DateTime.UtcNow
        };
    }
}
