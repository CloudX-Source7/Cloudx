using CloudX.EntraID.DTOs;
namespace CloudX.EntraID.Services.InactiveUser;

public interface IInactiveAccountService
{
    Task<List<InactiveAccountDto>> GetInactiveAccountsAsync(
        int inactiveDays = 90);
}