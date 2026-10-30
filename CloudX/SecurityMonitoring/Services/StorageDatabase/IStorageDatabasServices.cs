using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.StorageDatabase;

public interface IStorageDatabaseServices
{
    Task<List<SecurityFindingDto>> CheckStoragePublicBlobAsync(
        string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageSecureTransferAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageSharedKeyAccessAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlFirewallAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlEncryptionAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckSqlPrivateEndpointAsync(
    string entraTenantId);
    Task<List<SecurityFindingDto>> CheckStorageSharedAccessSignatureExpiryAsync(
    string entraTenantId);
    Task<List<UniversalResultDto>> ScanAsync(
    string entraTenantId);
}