using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.OrphanedAccount;

public interface IOrphanedAccountService
{
    Task<List<OrphanedAccountDto>> GetOrphanedAccountsAsync();
}