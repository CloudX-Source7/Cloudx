using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.PrivilegedAccount;

public interface IPrivilegedAccountService
{
    Task<List<PrivilegedAccountDto>>
        GetPrivilegedAccountsAsync();
}