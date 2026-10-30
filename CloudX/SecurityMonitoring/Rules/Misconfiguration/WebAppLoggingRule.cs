
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppLoggingRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppLoggingRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppLoggingAsync(
        ResourceDto resource)
    {
        if (!string.Equals(
                resource.Type,
                "Microsoft.Web/sites",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(resource.Id))
        {
            throw new InvalidOperationException(
                "The Web App resource ID is missing.");
        }

        var token = await _tokenAcquisition.GetAccessTokenForUserAsync(
            new[] { "https://management.azure.com/user_impersonation" },
            authenticationScheme:
                OpenIdConnectDefaults.AuthenticationScheme);

        using var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id}" +
            "/config/logs?api-version=2022-03-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve logging configuration for Web App " +
                $"'{resource.Name}'. HTTP {(int)response.StatusCode}: {body}",
                null,
                response.StatusCode);
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        if (!document.RootElement.TryGetProperty(
                "properties", out var properties) ||
            !properties.TryGetProperty(
                "applicationLogs", out var applicationLogs) ||
            applicationLogs.ValueKind != JsonValueKind.Object ||
            !applicationLogs.TryGetProperty(
                "fileSystem", out var fileSystem) ||
            fileSystem.ValueKind != JsonValueKind.Object ||
            !fileSystem.TryGetProperty(
                "level", out var levelProperty) ||
            levelProperty.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The Web App response does not contain a valid " +
                "applicationLogs.fileSystem.level value.");
        }

        var level = levelProperty.GetString();

        if (level is not ("Off" or "Error" or "Warning" or "Information" or "Verbose"))
        {
            throw new InvalidOperationException(
                $"The Web App has an unrecognized filesystem logging level: '{level}'.");
        }

        if (!string.Equals(
                level, "Off",
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
            Rule = "WebAppLogging",
            Severity = "Medium",
            Title = "Application Logging is not enabled",
            Description =
                "Application logging is disabled for the Azure Web App, which can make security monitoring and incident investigation more difficult.",
            Recommendation =
                "Enable application logging and configure an appropriate logging level for the Azure Web App.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
