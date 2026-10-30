using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.IdentityAccess;

public interface IIdentityAccessService
{
    Task<List<SecurityFindingDto>> CheckWebAppManagedIdentityAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppAuthenticationAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultAccessPolicyAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultRbacAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageRbacAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlAuthenticationAsync(
    string entraTenantId);
    Task<List<UniversalResultDto>> ScanAsync(
        string entraTenantId);
}