
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.Identity.Web;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace CloudX.SecurityMonitoring.Rules.Encryption;

public sealed class WebAppTlsRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppTlsRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppTlsAsync(
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
            authenticationScheme: OpenIdConnectDefaults.AuthenticationScheme);

        var client = _httpClientFactory.CreateClient();

        using var request = new HttpRequestMessage(
            HttpMethod.Get,
            $"https://management.azure.com{resource.Id.TrimEnd('/')}/config/web" +
            "?api-version=2022-03-01");

        request.Headers.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        using var response = await client.SendAsync(request);

        if (!response.IsSuccessStatusCode)
        {
            var details = await response.Content.ReadAsStringAsync();

            throw new HttpRequestException(
                $"Azure Web App TLS configuration request failed. " +
                $"Status: {(int)response.StatusCode} " +
                $"{response.ReasonPhrase}. Response: {details}");
        }

        await using var stream =
            await response.Content.ReadAsStreamAsync();

        using var document = await JsonDocument.ParseAsync(stream);

        var minTlsVersion = document.RootElement
            .TryGetProperty("properties", out var properties) &&
            properties.TryGetProperty(
                "minTlsVersion", out var tlsProperty)
                ? tlsProperty.GetString()
                : null;

        var tlsVersion = minTlsVersion?.Trim();

        if (string.IsNullOrWhiteSpace(tlsVersion) ||
            tlsVersion == "1.0" ||
            tlsVersion == "1.1")
        {
            var description = string.IsNullOrWhiteSpace(tlsVersion)
                ? $"The Azure Web App '{resource.Name}' does not have a minimum TLS version configured."
                : $"The Azure Web App '{resource.Name}' uses TLS {tlsVersion} as its minimum TLS version.";

            return new SecurityFindingDto
            {
                ResourceId = resource.Id,
                ResourceName = resource.Name,
                ResourceType = resource.Type,
                Category = "Encryption",
                Rule = "WebAppTls",
                Severity = "High",
                Title = "Web App uses an insecure TLS version",
                Description = description,
                Recommendation =
                    "Configure the Web App to use TLS 1.2 or higher as the minimum TLS version.",
                DetectedAt = DateTime.UtcNow
            };
        }

        return null;
    }
}
