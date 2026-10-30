using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;
using Microsoft.Graph.Models;

namespace CloudX.EntraID.Services.MfaEnforcement;

public class MfaEnforcementService : IMfaEnforcementService
{
    private readonly IEntraGraphClient _graphClient;

    public MfaEnforcementService(IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<MfaEnforcementDto>> GetMfaFindingsAsync()
    {
        var users =
            await _graphClient.GetUsersForMfaCheckAsync();

        var findings = new List<MfaEnforcementDto>();

        foreach (var user in users)
        {
            // Only check enabled member accounts.
            if (!string.Equals(
                    user.UserType,
                    "Member",
                    StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(user.Id))
            {
                continue;
            }

            var authenticationMethods =
                await _graphClient
                    .GetUserAuthenticationMethodsAsync(user.Id);

            var mfaMethods = authenticationMethods
                .Where(IsMfaMethod)
                .ToList();

            // User has at least one recognized MFA method.
            if (mfaMethods.Count > 0)
            {
                continue;
            }

            var defaultMfaMethod =
                mfaMethods
                    .FirstOrDefault()?
                    .OdataType?
                    .Replace("#microsoft.graph.", string.Empty)
                ?? string.Empty;

            findings.Add(new MfaEnforcementDto
            {
                Id = user.Id,

                DisplayName =
                    user.DisplayName ?? string.Empty,

                UserPrincipalName =
                    user.UserPrincipalName ?? string.Empty,

                UserType =
                    user.UserType ?? string.Empty,

                IsAdmin = false,

                IsMfaRegistered = false,

                IsMfaCapable = false,

                DefaultMfaMethod =
                    defaultMfaMethod,

                DetectionReason =
                    "No recognized MFA authentication method is registered for this user."
            });
        }

        return findings;
    }

    private static bool IsMfaMethod(
        AuthenticationMethod method)
    {
        var odataType =
            method.OdataType ?? string.Empty;

        return
            odataType.Contains(
                "microsoftAuthenticatorAuthenticationMethod",
                StringComparison.OrdinalIgnoreCase)
            ||
            odataType.Contains(
                "fido2AuthenticationMethod",
                StringComparison.OrdinalIgnoreCase)
            ||
            odataType.Contains(
                "phoneAuthenticationMethod",
                StringComparison.OrdinalIgnoreCase)
            ||
            odataType.Contains(
                "softwareOathAuthenticationMethod",
                StringComparison.OrdinalIgnoreCase)
            ||
            odataType.Contains(
                "windowsHelloForBusinessAuthenticationMethod",
                StringComparison.OrdinalIgnoreCase)
            ||
            odataType.Contains(
                "platformCredentialAuthenticationMethod",
                StringComparison.OrdinalIgnoreCase);
    }
}