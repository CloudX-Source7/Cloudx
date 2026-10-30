
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppAuthenticationRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppAuthenticationRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppAuthenticationAsync(
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

        async Task<JsonDocument> GetJsonAsync(string path)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://management.azure.com{path}");

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            using var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();

                throw new HttpRequestException(
                    $"ARM request failed for Web App '{resource.Name}'. " +
                    $"HTTP {(int)response.StatusCode}: {body}",
                    null,
                    response.StatusCode);
            }

            await using var stream =
                await response.Content.ReadAsStreamAsync();

            return await JsonDocument.ParseAsync(stream);
        }

        using var authSettingsDocument = await GetJsonAsync(
            $"{resource.Id}/config/authsettings?api-version=2022-03-01");

        var authSettingsRoot = authSettingsDocument.RootElement;

        var configVersion = GetString(
            authSettingsRoot, "properties", "configVersion")
            ?.ToLowerInvariant();

        // V2: modern App Service Authentication.
        if (configVersion == "v2")
        {
            using var authV2Document = await GetJsonAsync(
                $"{resource.Id}/config/authsettingsV2?api-version=2022-03-01");

            var root = authV2Document.RootElement;

            var authenticationEnabled =
                GetBoolean(root, "properties", "platform", "enabled");

            var authenticationRequired =
                GetBoolean(root, "properties", "globalValidation",
                    "requireAuthentication");

            if (authenticationEnabled == true &&
                authenticationRequired == true)
            {
                return null;
            }

            return CreateFinding(
                resource,
                "High",
                "App Service Authentication is not enabled",
                "The Azure Web App uses App Service Authentication V2, " +
                "but authentication is not both enabled and required for incoming requests.",
                "Enable App Service Authentication V2 and require authentication for the Azure Web App.",
                "v2");
        }

        // V1: classic App Service Authentication.
        if (configVersion == "v1")
        {
            var authenticationEnabled =
                GetBoolean(authSettingsRoot, "properties", "enabled");

            if (authenticationEnabled == true)
            {
                return null;
            }

            var defaultProvider =
                GetString(authSettingsRoot, "properties", "defaultProvider")
                ?? "None";

            var unauthenticatedAction =
                GetString(authSettingsRoot, "properties",
                    "unauthenticatedClientAction")
                ?? "None";

            return CreateFinding(
                resource,
                "High",
                "App Service Authentication is not enabled",
                "The Azure Web App uses App Service Authentication V1 (classic), " +
                "but authentication is not enabled. " +
                $"Default provider: {defaultProvider}. " +
                $"Unauthenticated client action: {unauthenticatedAction}.",
                "Enable App Service Authentication for the Azure Web App and configure an appropriate identity provider.",
                "v1");
        }

        // Do not report an unknown configuration as a confirmed vulnerability.
        throw new InvalidOperationException(
            "Unable to identify the Web App Authentication configuration version. " +
            $"Received: '{configVersion ?? "Unknown"}'.");

    }

    private static SecurityFindingDto CreateFinding(
        ResourceDto resource,
        string severity,
        string title,
        string description,
        string recommendation,
        string configurationVersion)
    {
        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "WebAppAuthentication",
            Severity = severity,
            Title = title,
            Description = description,
            Recommendation = recommendation,
            ConfigurationVersion = configurationVersion,
            DetectedAt = DateTime.UtcNow
        };
    }

    private static string? GetString(
        JsonElement root,
        params string[] path)
    {
        var element = root;

        foreach (var propertyName in path)
        {
            if (element.ValueKind != JsonValueKind.Object ||
                !element.TryGetProperty(propertyName, out element))
            {
                return null;
            }
        }

        return element.ValueKind == JsonValueKind.String
            ? element.GetString()
            : null;
    }

    private static bool? GetBoolean(
        JsonElement root,
        params string[] path)
    {
        var element = root;

        foreach (var propertyName in path)
        {
            if (element.ValueKind != JsonValueKind.Object ||
                !element.TryGetProperty(propertyName, out element))
            {
                return null;
            }
        }

        return element.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }
}
