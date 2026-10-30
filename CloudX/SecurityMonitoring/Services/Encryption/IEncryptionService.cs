
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.Encryption;

public interface IEncryptionService
{
    Task<List<SecurityFindingDto>> CheckStorageEncryptionAsync(
        string entraTenantId);

    Task<List<SecurityFindingDto>> CheckStorageCustomerManagedKeyAsync(
        string entraTenantId);

    Task<List<SecurityFindingDto>> CheckSqlEncryptionAsync(
        string entraTenantId);

    Task<List<SecurityFindingDto>> CheckSqlCustomerManagedKeyAsync(
        string entraTenantId);

    Task<List<SecurityFindingDto>> CheckKeyVaultKeyProtectionAsync(
        string entraTenantId);

    Task<List<SecurityFindingDto>> CheckWebAppTlsAsync(
        string entraTenantId);

    // Existing tenant-wide scan
    Task<List<UniversalResultDto>> ScanAsync(
        string entraTenantId);

    // New selected-subscription scan
    Task<List<UniversalResultDto>> ScanAsync(
        string entraTenantId,
        string subscriptionId);
}
