
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.NetworkFirewall;

public sealed class SubnetMissingNsgRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SubnetMissingNsgRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSubnetMissingNsgAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Network/virtualNetworks/subnets",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The subnet resource ID is missing.");
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
                $"Failed to retrieve subnet configuration. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("properties", out var properties))
        {
            throw new InvalidOperationException(
                "The subnet response did not contain a properties object.");
        }

        if (!properties.TryGetProperty(
                "networkSecurityGroup", out var nsgProperty))
        {
            throw new InvalidOperationException(
                "The subnet response did not contain the networkSecurityGroup property.");
        }

        if (nsgProperty.ValueKind == JsonValueKind.Object)
        {
            return null;
        }

        if (nsgProperty.ValueKind != JsonValueKind.Null)
        {
            throw new InvalidOperationException(
                "The subnet networkSecurityGroup property has an unexpected value.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "NetworkFirewall",
            Rule = "SubnetMissingNsg",
            Severity = "Medium",
            Title = "Subnet does not have a Network Security Group",
            Description =
                $"The Azure subnet '{resource.Name}' does not have a " +
                "Network Security Group associated with it.",
            Recommendation =
                "Associate a Network Security Group with the subnet to " +
                "control inbound and outbound network traffic.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
