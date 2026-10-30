using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.ExcessivePrivilege;

public interface IExcessivePrivilegeService
{
    Task<List<ExcessivePrivilegeDto>>
        GetExcessivePrivilegeFindingsAsync();
}