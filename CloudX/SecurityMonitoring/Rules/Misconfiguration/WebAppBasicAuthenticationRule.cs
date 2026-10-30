
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppBasicAuthenticationRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppBasicAuthenticationRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppBasicAuthenticationAsync(
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

        async Task<JsonDocument> GetPolicyAsync(string endpoint)
        {
            using var request = new HttpRequestMessage(
                HttpMethod.Get,
                $"https://management.azure.com{resource.Id}/{endpoint}" +
                "?api-version=2022-03-01");

            request.Headers.Authorization =
                new AuthenticationHeaderValue("Bearer", token);

            using var response = await client.SendAsync(request);

            if (!response.IsSuccessStatusCode)
            {
                var body = await response.Content.ReadAsStringAsync();

                throw new HttpRequestException(
                    $"Failed to retrieve publishing credentials policy " +
                    $"for Web App '{resource.Name}'. " +
                    $"HTTP {(int)response.StatusCode}: {body}",
                    null,
                    response.StatusCode);
            }

            await using var stream =
                await response.Content.ReadAsStreamAsync();

            return await JsonDocument.ParseAsync(stream);
        }

        using var scmDocument = await GetPolicyAsync(
            "basicPublishingCredentialsPolicies/scm");

        using var ftpDocument = await GetPolicyAsync(
            "basicPublishingCredentialsPolicies/ftp");

        var scmAllowed = GetAllowValue(scmDocument.RootElement);
        var ftpAllowed = GetAllowValue(ftpDocument.RootElement);

        if (scmAllowed == false && ftpAllowed == false)
        {
            return null;
        }

        if (scmAllowed is null || ftpAllowed is null)
        {
            throw new InvalidOperationException(
                "The Web App publishing credentials policy response " +
                "is missing a valid properties.allow value.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "WebAppBasicAuthentication",
            Severity = "Medium",
            Title = "Basic Authentication is enabled",
            Description =
                "Basic Authentication is enabled for one or more Azure App Service deployment endpoints.",
            Recommendation =
                "Disable SCM and FTP Basic Authentication and use Microsoft Entra ID-based authentication or another secure deployment method.",
            DetectedAt = DateTime.UtcNow
        };
    }

    private static bool? GetAllowValue(JsonElement root)
    {
        if (!root.TryGetProperty("properties", out var properties) ||
            !properties.TryGetProperty("allow", out var allow))
        {
            return null;
        }

        return allow.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            _ => null
        };
    }
}
