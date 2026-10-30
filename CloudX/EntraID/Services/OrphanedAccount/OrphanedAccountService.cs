using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;

namespace CloudX.EntraID.Services.OrphanedAccount;

public class OrphanedAccountService : IOrphanedAccountService
{
    private readonly IEntraGraphClient _graphClient;

    public OrphanedAccountService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<OrphanedAccountDto>> GetOrphanedAccountsAsync()
    {
        var users =
            await _graphClient.GetUsersForOrphanDetectionAsync();

        var orphanedAccounts = users
            .Where(user =>
                user.AccountEnabled == true &&
                string.Equals(
                    user.UserType,
                    "Member",
                    StringComparison.OrdinalIgnoreCase) &&
                user.Manager == null &&
                string.IsNullOrWhiteSpace(user.EmployeeId) &&
                string.IsNullOrWhiteSpace(user.Department) &&
                string.IsNullOrWhiteSpace(user.JobTitle))
            .Select(user => new OrphanedAccountDto
            {
                Id =
                    user.Id ?? string.Empty,

                DisplayName =
                    user.DisplayName ?? string.Empty,

                UserPrincipalName =
                    user.UserPrincipalName ?? string.Empty,

                AccountEnabled =
                    user.AccountEnabled,

                UserType =
                    user.UserType ?? string.Empty,

                Department =
                    user.Department ?? string.Empty,

                JobTitle =
                    user.JobTitle ?? string.Empty,

                EmployeeId =
                    user.EmployeeId ?? string.Empty,

                ManagerDisplayName =
                    user.Manager?.AdditionalData?
                        .TryGetValue("displayName", out var managerName) == true
                            ? managerName?.ToString() ?? string.Empty
                            : string.Empty,

                DetectionReason =
                    "Enabled member account has no manager, employee ID, department, or job title."
            })
            .ToList();

        return orphanedAccounts;
    }
}