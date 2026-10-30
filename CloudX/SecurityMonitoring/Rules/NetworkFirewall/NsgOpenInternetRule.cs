
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.NetworkFirewall;

public sealed class NsgOpenInternetRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public NsgOpenInternetRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckNsgOpenInternetAsync(
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

            var sources = GetStringArray(
                ruleProperties, "sourceAddressPrefixes");

            var source = GetString(
                ruleProperties, "sourceAddressPrefix");

            if (sources.Count == 0 && source is not null)
            {
                sources.Add(source);
            }

            var internetSource = sources.Any(value =>
                value == "*" ||
                value == "0.0.0.0/0" ||
                value == "::/0" ||
                string.Equals(value, "Internet",
                    StringComparison.OrdinalIgnoreCase));

            var ports = GetStringArray(
                ruleProperties, "destinationPortRanges");

            var port = GetString(
                ruleProperties, "destinationPortRange");

            if (ports.Count == 0 && port is not null)
            {
                ports.Add(port);
            }

            var anyPort = ports.Any(value => value == "*");

            if (!internetSource || !anyPort)
            {
                continue;
            }

            return new SecurityFindingDto
            {
                ResourceId = resource.Id,
                ResourceName = resource.Name,
                ResourceType = resource.Type,
                Category = "NetworkFirewall",
                Rule = "NsgOpenInternet",
                Severity = "Critical",
                Title =
                    "Network Security Group allows unrestricted internet access",
                Description =
                    $"The Network Security Group '{resource.Name}' contains " +
                    "an inbound allow rule that permits traffic from the " +
                    "internet to any destination port.",
                Recommendation =
                    "Restrict inbound access to trusted source IP addresses, " +
                    "required ports, and necessary protocols.",
                DetectedAt = DateTime.UtcNow
            };
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
