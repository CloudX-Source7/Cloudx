using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;

namespace CloudX.EntraID.Services.PrivilegedAccount;

public class PrivilegedAccountService
    : IPrivilegedAccountService
{
    private readonly IEntraGraphClient _graphClient;

    public PrivilegedAccountService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<PrivilegedAccountDto>>
        GetPrivilegedAccountsAsync()
    {
        var assignments =
            await _graphClient
                .GetDirectoryRoleAssignmentsAsync();

        var definitions =
            await _graphClient
                .GetDirectoryRoleDefinitionsAsync();

        var roleDefinitions =
            definitions
                .Where(role =>
                    !string.IsNullOrWhiteSpace(role.Id))
                .ToDictionary(
                    role => role.Id!,
                    role => role.DisplayName ?? "Unknown Role",
                    StringComparer.OrdinalIgnoreCase);

        var findings =
            new List<PrivilegedAccountDto>();

        foreach (var assignment in assignments)
        {
            if (string.IsNullOrWhiteSpace(
                    assignment.PrincipalId))
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(
                    assignment.RoleDefinitionId))
            {
                continue;
            }

            var roleName =
                roleDefinitions.TryGetValue(
                    assignment.RoleDefinitionId,
                    out var resolvedRoleName)
                    ? resolvedRoleName
                    : "Unknown Role";

            Microsoft.Graph.Models.User? user;

            try
            {
                user =
                    await _graphClient
                        .GetUserByIdAsync(
                            assignment.PrincipalId);
            }
            catch
            {
                // The principal may be a group,
                // service principal, or another
                // directory object instead of a user.
                continue;
            }

            if (user == null)
            {
                continue;
            }

            findings.Add(
                new PrivilegedAccountDto
                {
                    UserId =
                        user.Id ?? string.Empty,

                    DisplayName =
                        user.DisplayName ?? string.Empty,

                    UserPrincipalName =
                        user.UserPrincipalName ?? string.Empty,

                    UserType =
                        user.UserType ?? string.Empty,

                    AccountEnabled =
                        user.AccountEnabled,

                    RoleName =
                        roleName,

                    RoleDefinitionId =
                        assignment.RoleDefinitionId,

                    DirectoryScope =
                        string.IsNullOrWhiteSpace(
                            assignment.DirectoryScopeId)
                            ? "/"
                            : assignment.DirectoryScopeId,

                    DetectionReason =
                        $"User has the Microsoft Entra " +
                        $"directory role '{roleName}'."
                });
        }

        return findings
            .OrderBy(account => account.DisplayName)
            .ThenBy(account => account.RoleName)
            .ToList();
    }
}