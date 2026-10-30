
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.StorageDatabase;

public sealed class SqlPrivateEndpointRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public SqlPrivateEndpointRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckSqlPrivateEndpointAsync(
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
            "/privateEndpointConnections" +
            "?api-version=2023-08-01";

        using var request = new HttpRequestMessage(HttpMethod.Get, url);

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                $"Failed to retrieve SQL Server private endpoint connections. " +
                $"HTTP {(int)response.StatusCode}: {body}");
        }

        using var document = JsonDocument.Parse(body);
        var root = document.RootElement;

        if (!root.TryGetProperty("value", out var connections) ||
            connections.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The SQL Server response did not contain a valid " +
                "private endpoint connections array.");
        }

        var hasApprovedConnection = false;

        foreach (var connection in connections.EnumerateArray())
        {
            if (!connection.TryGetProperty(
                    "properties", out var properties))
            {
                continue;
            }

            if (!properties.TryGetProperty(
                    "privateLinkServiceConnectionState", out var state))
            {
                continue;
            }

            if (state.TryGetProperty("status", out var statusProperty) &&
                statusProperty.ValueKind == JsonValueKind.String &&
                string.Equals(
                    statusProperty.GetString(),
                    "Approved",
                    StringComparison.OrdinalIgnoreCase))
            {
                hasApprovedConnection = true;
                break;
            }
        }

        if (hasApprovedConnection)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "StorageDatabase",
            Rule = "SqlPrivateEndpoint",
            Severity = "High",
            Title = "SQL Server does not have an approved private endpoint",
            Description =
                $"The Azure SQL Server '{resource.Name}' does not have an " +
                "approved private endpoint connection.",
            Recommendation =
                "Configure and approve an Azure Private Endpoint for the " +
                "SQL Server, and verify its private DNS and network connectivity.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
