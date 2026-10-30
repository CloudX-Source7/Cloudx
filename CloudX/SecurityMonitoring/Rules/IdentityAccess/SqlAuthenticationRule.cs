
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.IdentityAccess;

public sealed class SqlAuthenticationRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SqlAuthenticationRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSqlAuthenticationAsync(
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
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "/azureADOnlyAuthentications/Default" +
            "?api-version=2023-08-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve SQL Server Entra-only authentication " +
                $"configuration. HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty(
                "azureADOnlyAuthentication", out var property) ||
            (property.ValueKind != JsonValueKind.True &&
             property.ValueKind != JsonValueKind.False))
        {
            throw new InvalidOperationException(
                "The SQL Server response did not contain a valid " +
                "azureADOnlyAuthentication property.");
        }

        var entraOnlyEnabled = property.GetBoolean();

        if (entraOnlyEnabled)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "IdentityAccess",
            Rule = "SqlAuthentication",
            Severity = "High",
            Title = "SQL Server allows SQL authentication",
            Description =
                "The Azure SQL Server does not require Microsoft Entra-only " +
                "authentication, allowing SQL authentication with SQL credentials.",
            Recommendation =
                "Enable Microsoft Entra-only authentication for the Azure SQL " +
                "Server and use Microsoft Entra identities for authentication.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
