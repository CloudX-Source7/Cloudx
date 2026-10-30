using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.AccountDisable;

public interface IAccountDisableService
{
    Task<AccountDisableDto> DisableAccountAsync(
        string userId);
}