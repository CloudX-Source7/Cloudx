using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services;

public interface IMisconfigurationService
{
    Task<List<SecurityFindingDto>> CheckWebAppHttpsOnlyAsync(
    string entraTenantId);

    Task<List<SecurityFindingDto>> CheckWebAppAuthenticationAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppManagedIdentityAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppRemoteDebuggingAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppBasicAuthenticationAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppCorsAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppFtpStateAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckWebAppLoggingAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlPublicNetworkAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlFirewallRuleAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlTlsAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStoragePublicAccessAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageSecureTransferAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageNetworkAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultPublicNetworkAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultSoftDeleteAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckKeyVaultPurgeProtectionAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckActivityLogAlertMissingAsync(
    string entraTenantId);
    Task<List<UniversalResultDto>> ScanAsync(
    string entraTenantId);
}