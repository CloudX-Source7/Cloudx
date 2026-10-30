using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;

namespace CloudX.EntraID.Services.EntraUser;

public class EntraUserService : IEntraUserService
{
    private readonly IEntraGraphClient _graphClient;

    public EntraUserService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<EntraUserDto>> GetUsersAsync()
    {
        var users = await _graphClient.GetUsersAsync();

        return users.Select(user => new EntraUserDto
        {
            Id = user.Id ?? string.Empty,
            DisplayName = user.DisplayName ?? string.Empty,
            UserPrincipalName =
                user.UserPrincipalName ?? string.Empty,
            Mail = user.Mail ?? string.Empty,
            AccountEnabled = user.AccountEnabled,
            UserType = user.UserType ?? string.Empty,
            JobTitle = user.JobTitle ?? string.Empty,
            Department = user.Department ?? string.Empty,
            CreatedDateTime = user.CreatedDateTime
        }).ToList();
    }
}