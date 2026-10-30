
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class ActivityLogAlertMissingRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public ActivityLogAlertMissingRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?>
        CheckActivityLogAlertMissingAsync(ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Resources/subscriptions",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The subscription resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "/providers/Microsoft.Insights/activityLogAlerts" +
            "?api-version=2020-10-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve Activity Log Alerts for " +
                $"subscription '{resource.Name}'. " +
                $"HTTP {(int)response.StatusCode}: {body}",
                null,
                response.StatusCode);
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        if (!document.RootElement.TryGetProperty(
                "value", out var alerts) ||
            alerts.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The Activity Log Alerts response is missing " +
                "the expected value array.");
        }

        foreach (var alert in alerts.EnumerateArray())
        {
            if (!alert.TryGetProperty(
                    "properties", out var properties))
            {
                continue;
            }

            if (properties.TryGetProperty(
                    "enabled", out var enabled) &&
                enabled.ValueKind == JsonValueKind.True)
            {
                return null;
            }
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "ActivityLogAlertMissing",
            Severity = "High",
            Title = "Azure Activity Log alert is missing",
            Description =
                $"The Azure subscription '{resource.Name}' " +
                "does not have an enabled Activity Log Alert.",
            Recommendation =
                "Create and enable Activity Log Alerts for " +
                "important subscription-level administrative events.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
