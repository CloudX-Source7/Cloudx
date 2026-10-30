
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.NetworkFirewall;

public sealed class NsgBroadInboundRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public NsgBroadInboundRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckNsgBroadInboundAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Network/networkSecurityGroups",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The Network Security Group resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        var url =
            $"https://management.azure.com{resource.Id.TrimEnd('/')}" +
            "?api-version=2024-05-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve NSG configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty(
                "securityRules", out var securityRules) ||
            securityRules.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The NSG response did not contain a valid securityRules array.");
        }

        foreach (var rule in securityRules.EnumerateArray())
        {
            if (!rule.TryGetProperty("properties", out var ruleProperties))
            {
                continue;
            }

            var direction = GetString(ruleProperties, "direction");
            var access = GetString(ruleProperties, "access");

            if (!string.Equals(direction, "Inbound",
                    StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(access, "Allow",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var sourcePrefixes = GetStringArray(
                ruleProperties, "sourceAddressPrefixes");

            var sourcePrefix = GetString(
                ruleProperties, "sourceAddressPrefix");

            if (sourcePrefixes.Count == 0 && sourcePrefix is not null)
            {
                sourcePrefixes.Add(sourcePrefix);
            }

            var destinationPrefixes = GetStringArray(
                ruleProperties, "destinationPortRanges");

            var destinationPort = GetString(
                ruleProperties, "destinationPortRange");

            if (destinationPrefixes.Count == 0 &&
                destinationPort is not null)
            {
                destinationPrefixes.Add(destinationPort);
            }

            var sourceIsInternet = sourcePrefixes.Any(prefix =>
                prefix == "*" ||
                prefix.Equals("Internet", StringComparison.OrdinalIgnoreCase) ||
                prefix == "0.0.0.0/0" ||
                prefix == "::/0");

            var allowsBroadPorts = destinationPrefixes.Any(port =>
                port == "*" ||
                port == "0-65535");

            if (sourceIsInternet && allowsBroadPorts)
            {
                return new SecurityFindingDto
                {
                    ResourceId = resource.Id,
                    ResourceName = resource.Name,
                    ResourceType = resource.Type,
                    Category = "NetworkFirewall",
                    Rule = "NsgBroadInbound",
                    Severity = "High",
                    Title =
                        "Network Security Group allows broad inbound access",
                    Description =
                        $"The Network Security Group '{resource.Name}' " +
                        "contains an inbound allow rule that permits traffic " +
                        "from the internet across a broad range of ports.",
                    Recommendation =
                        "Restrict inbound rules to trusted source IP addresses " +
                        "and only the ports required by the application.",
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

    private static List<string> GetStringArray(
        JsonElement element,
        string propertyName)
    {
        var values = new List<string>();

        if (element.TryGetProperty(propertyName, out var property) &&
            property.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in property.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String)
                {
                    var value = item.GetString();

                    if (!string.IsNullOrWhiteSpace(value))
                    {
                        values.Add(value);
                    }
                }
            }
        }

        return values;
    }
}
