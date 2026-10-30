using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.PublicExposure;

public interface IPublicExposureService
{
    Task<List<SecurityFindingDto>> CheckWebAppPublicAccessAsync(
        string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlPublicAccessAsync(
       string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStoragePublicBlobAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultPublicNetworkAsync(
    string entraTenantId);
    Task<List<UniversalResultDto>> ScanAsync(
     string entraTenantId);
}