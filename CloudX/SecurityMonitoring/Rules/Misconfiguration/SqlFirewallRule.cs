
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

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

    public async Task<SecurityFindingDto?> CheckSqlFirewallRuleAsync(
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
            "/firewallRules?api-version=2023-08-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve firewall rules for SQL Server " +
                $"'{resource.Name}'. HTTP {(int)response.StatusCode}: {body}",
                null,
                response.StatusCode);
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        if (!document.RootElement.TryGetProperty(
                "value", out var firewallRules) ||
            firewallRules.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The SQL firewall response is missing the expected value array.");
        }

        foreach (var firewallRule in firewallRules.EnumerateArray())
        {
            if (!firewallRule.TryGetProperty(
                    "properties", out var properties))
            {
                continue;
            }

            var startIp = GetString(properties, "startIpAddress");
            var endIp = GetString(properties, "endIpAddress");

            if (string.Equals(startIp, "0.0.0.0",
                    StringComparison.OrdinalIgnoreCase) &&
                string.Equals(endIp, "255.255.255.255",
                    StringComparison.OrdinalIgnoreCase))
            {
                return new SecurityFindingDto
                {
                    ResourceId = resource.Id,
                    ResourceName = resource.Name,
                    ResourceType = resource.Type,
                    Category = "Misconfiguration",
                    Rule = "SqlFirewallRule",
                    Severity = "High",
                    Title =
                        "SQL Firewall allows access from all IPv4 addresses",
                    Description =
                        "The Azure SQL Server has a firewall rule that allows connections from any IPv4 address.",
                    Recommendation =
                        "Remove the unrestricted firewall rule and allow only trusted IP addresses or private network access.",
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
