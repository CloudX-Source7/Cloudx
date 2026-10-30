
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class SqlTlsRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SqlTlsRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSqlTlsAsync(
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
                "minimalTlsVersion", out var tlsProperty) ||
            tlsProperty.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The SQL Server response does not contain a valid " +
                "properties.minimalTlsVersion value.");
        }

        var tlsVersion = tlsProperty.GetString();

        if (string.Equals(tlsVersion, "1.2",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(tlsVersion, "1.3",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "SqlTls",
            Severity = "High",
            Title = "SQL Server minimum TLS version is too low",
            Description =
                $"The Azure SQL Server minimum TLS version is configured as {tlsVersion}.",
            Recommendation =
                "Configure the Azure SQL Server to require TLS 1.2 or higher.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
