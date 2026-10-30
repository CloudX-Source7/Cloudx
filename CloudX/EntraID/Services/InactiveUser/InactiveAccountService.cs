using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;
using Microsoft.Graph.Models.ODataErrors;

namespace CloudX.EntraID.Services.InactiveUser;

public class InactiveAccountService : IInactiveAccountService
{
    private readonly IEntraGraphClient _graphClient;

    public InactiveAccountService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<InactiveAccountDto>> GetInactiveAccountsAsync(
        int inactiveDays = 90)
    {
        List<Microsoft.Graph.Models.User> users;

        try
        {
            users =
                await _graphClient.GetUsersWithSignInActivityAsync();
        }
        catch (ODataError ex)
        {
            throw new InvalidOperationException(
                "Inactive account detection is unavailable for this tenant. " +
                "Microsoft Entra ID Premium licensing and the required " +
                "Microsoft Graph permissions are required.",
                ex);
        }

        var cutoffDate =
            DateTimeOffset.UtcNow.AddDays(-inactiveDays);

        var inactiveUsers = users
            .Where(user =>
                user.AccountEnabled == true &&
                (
                    user.SignInActivity?.LastSignInDateTime == null ||
                    user.SignInActivity.LastSignInDateTime < cutoffDate
                ))
            .Select(user => new InactiveAccountDto
            {
                Id = user.Id ?? string.Empty,

                DisplayName =
                    user.DisplayName ?? string.Empty,

                UserPrincipalName =
                    user.UserPrincipalName ?? string.Empty,

                LastSignInDateTime =
                    user.SignInActivity?.LastSignInDateTime,

                InactiveDays =
                    user.SignInActivity?.LastSignInDateTime != null
                        ? (int)(
                            DateTimeOffset.UtcNow -
                            user.SignInActivity.LastSignInDateTime.Value
                          ).TotalDays
                        : null,

                AccountEnabled =
                    user.AccountEnabled,

                UserType =
                    user.UserType ?? string.Empty
            })
            .ToList();

        return inactiveUsers;
    }
}