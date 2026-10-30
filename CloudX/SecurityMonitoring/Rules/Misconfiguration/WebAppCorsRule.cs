
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppCorsRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppCorsRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppCorsAsync(
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
            "/config/web?api-version=2022-03-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Failed to retrieve CORS configuration for Web App " +
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
                "cors", out var cors) ||
            cors.ValueKind != JsonValueKind.Object ||
            !cors.TryGetProperty(
                "allowedOrigins", out var origins) ||
            origins.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException(
                "The Web App response does not contain a valid " +
                "CORS allowedOrigins configuration.");
        }

        var allowsAllOrigins = origins.EnumerateArray().Any(origin =>
            origin.ValueKind == JsonValueKind.String &&
            string.Equals(
                origin.GetString(),
                "*",
                StringComparison.Ordinal));

        if (!allowsAllOrigins)
        {
            return null;
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "WebAppCors",
            Severity = "Medium",
            Title = "CORS allows all origins",
            Description =
                "The Azure Web App CORS configuration allows requests from any origin.",
            Recommendation =
                "Restrict CORS to only trusted and required origins instead of allowing all origins.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
