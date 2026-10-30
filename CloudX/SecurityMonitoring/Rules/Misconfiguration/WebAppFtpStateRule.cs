
using System.Net.Http.Headers;
using System.Text.Json;
using CloudX.AzureDiscovery.Dto;
using CloudX.SecurityMonitoring.Dto;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Identity.Web;

namespace CloudX.SecurityMonitoring.Rules.Misconfiguration;

public sealed class WebAppFtpStateRule
{
    private readonly ITokenAcquisition _tokenAcquisition;
    private readonly IHttpClientFactory _httpClientFactory;

    public WebAppFtpStateRule(
        ITokenAcquisition tokenAcquisition,
        IHttpClientFactory httpClientFactory)
    {
        _tokenAcquisition = tokenAcquisition;
        _httpClientFactory = httpClientFactory;
    }

    public async Task<SecurityFindingDto?> CheckWebAppFtpStateAsync(
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
                $"Failed to retrieve FTP configuration for Web App " +
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
                "ftpsState", out var ftpsState) ||
            ftpsState.ValueKind != JsonValueKind.String)
        {
            throw new InvalidOperationException(
                "The Web App response does not contain a valid " +
                "properties.ftpsState value.");
        }

        var state = ftpsState.GetString();

        if (string.Equals(
                state, "FtpsOnly",
                StringComparison.OrdinalIgnoreCase) ||
            string.Equals(
                state, "Disabled",
                StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (!string.Equals(
                state, "AllAllowed",
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                $"The Web App has an unrecognized ftpsState value: '{state}'.");
        }

        return new SecurityFindingDto
        {
            ResourceId = resource.Id,
            ResourceName = resource.Name,
            ResourceType = resource.Type,
            Category = "Misconfiguration",
            Rule = "WebAppFtpState",
            Severity = "Medium",
            Title = "FTP access is allowed",
            Description =
                "The Azure Web App allows FTP connections in addition to FTPS, which permits unencrypted file transfer.",
            Recommendation =
                "Disable FTP access and configure the Web App to allow FTPS only, or disable FTP/FTPS completely if file transfer is not required.",
            DetectedAt = DateTime.UtcNow
        };
    }
}
