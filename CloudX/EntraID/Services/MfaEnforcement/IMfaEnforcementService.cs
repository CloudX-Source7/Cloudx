using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.MfaEnforcement;

public interface IMfaEnforcementService
{
    Task<List<MfaEnforcementDto>>
        GetMfaFindingsAsync();
}   