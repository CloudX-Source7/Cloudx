
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.StorageDatabase;

public sealed class SqlFirewallRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SqlFirewallRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSqlFirewallAsync(
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
            "/firewallRules?api-version=2023-08-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve SQL Server firewall rules. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("value", out var firewallRules) ||
            firewallRules.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The SQL Server response did not contain a valid firewall rules array.");
        }

        foreach (var firewallRule in firewallRules.EnumerateArray())
        {
            if (!firewallRule.TryGetProperty(
                    "properties", out var properties))
            {
                continue;
            }

            var startIpAddress = GetString(properties, "startIpAddress");
            var endIpAddress = GetString(properties, "endIpAddress");

            if (string.Equals(
                    startIpAddress,
                    "0.0.0.0",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(
                    endIpAddress,
                    "0.0.0.0",
                    StringComparison.OrdinalIgnoreCase))
            {
                return new SecurityFindingDto
                {
                    ResourceId = resource.Id,
                    ResourceName = resource.Name,
                    ResourceType = resource.Type,
                    Category = "StorageDatabase",
                    Rule = "SqlFirewall",
                    Severity = "Critical",
                    Title = "SQL Server allows Azure-wide firewall access",
                    Description =
                        $"The Azure SQL Server '{resource.Name}' has a " +
                        "firewall rule that allows access from Azure services.",
                    Recommendation =
                        "Remove the 0.0.0.0 firewall rule and restrict network " +
                        "access to trusted sources or use a private endpoint.",
                    DetectedAt = DateTime.UtcNow
                };
            }
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
}
