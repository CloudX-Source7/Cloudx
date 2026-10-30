using Microsoft.Graph.Models;

namespace CloudX.EntraID.Graph;

public interface IEntraGraphClient
{
    Task<List<User>> GetUsersAsync();

    Task<List<User>> GetUsersWithSignInActivityAsync();

    Task<List<User>> GetUsersForOrphanDetectionAsync();

    Task<List<User>> GetUsersForDepartedEmployeeDetectionAsync();

    Task<List<User>> GetUsersForMfaCheckAsync();

    Task<List<AuthenticationMethod>> GetUserAuthenticationMethodsAsync(
        string userId);
    Task<List<Microsoft.Graph.Models.UnifiedRoleAssignment>>
    GetDirectoryRoleAssignmentsAsync();

    Task<List<Microsoft.Graph.Models.UnifiedRoleDefinition>>
        GetDirectoryRoleDefinitionsAsync();

    Task<Microsoft.Graph.Models.User?>
        GetUserByIdAsync(string userId);
    Task DisableUserAsync(string userId);
}