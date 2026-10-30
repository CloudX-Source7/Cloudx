
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class SqlPublicNetworkRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SqlPublicNetworkRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSqlPublicNetworkAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Sql/servers",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The SQL Server resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "?api-version=2023-08-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve SQL Server '{resource.Name}'. " +
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
                "The SQL Server response does not contain a valid " +
                "properties.publicNetworkAccess value.");
        }

        var access = publicAccess.GetString();

        if (string.Equals(
                access,
                "Disabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.Equals(
                access,
                "Enabled",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"SQL Server public network access has an unrecognized " +
                $"value: '{access}'.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "SqlPublicNetworkRule",
            Severity = "High",
            Title = "SQL Server public network access is enabled",
            Description =
                "The Azure SQL Server allows access through its public network endpoint.",
            Recommendation =
                "Disable public network access and use private connectivity such as a private endpoint whenever possible.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
