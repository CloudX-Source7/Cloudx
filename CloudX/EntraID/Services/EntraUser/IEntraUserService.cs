using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.EntraUser;

public interface IEntraUserService
{
    Task<List<EntraUserDto>> GetUsersAsync();
}