using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.StorageDatabase;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.StorageDatabase;

public class StorageDatabaseService : IStorageDatabaseServices
{
    private readonly IAzureDiscoveryService _discoveryService;
    private readonly StoragePublicBlobRule _storagePublicBlobRule;
    private readonly StorageSecureTransferRule _storageSecureTransferRule;
    private readonly StorageSharedKeyAccessRule _storageSharedKeyAccessRule;
    private readonly SqlFirewallRule _sqlFirewallRule;
    private readonly SqlEncryptionRule _sqlEncryptionRule;
    private readonly SqlPrivateEndpointRule _sqlPrivateEndpointRule;
    private readonly StorageSharedAccessSignatureExpiryRule _storageSharedAccessSignatureExpiryRule;

    public StorageDatabaseService(
    IAzureDiscoveryService discoveryService,
    StoragePublicBlobRule storagePublicBlobRule,
    StorageSecureTransferRule storageSecureTransferRule,
    StorageSharedKeyAccessRule storageSharedKeyAccessRule,
    SqlFirewallRule sqlFirewallRule,
    SqlEncryptionRule sqlEncryptionRule,
    SqlPrivateEndpointRule sqlPrivateEndpointRule,
    StorageSharedAccessSignatureExpiryRule storageSharedAccessSignatureExpiryRule)
    {
        _discoveryService = discoveryService;
        _storagePublicBlobRule = storagePublicBlobRule;
        _storageSecureTransferRule = storageSecureTransferRule;
        _storageSharedKeyAccessRule = storageSharedKeyAccessRule;
        _sqlFirewallRule = sqlFirewallRule;
        _sqlEncryptionRule = sqlEncryptionRule;
        _sqlPrivateEndpointRule = sqlPrivateEndpointRule;
        _storageSharedAccessSignatureExpiryRule =
            storageSharedAccessSignatureExpiryRule;
    }

    public async Task<List<SecurityFindingDto>>
        CheckStoragePublicBlobAsync(
            string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _storagePublicBlobRule
                    .CheckStoragePublicBlobAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckStorageSecureTransferAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _storageSecureTransferRule
                    .CheckStorageSecureTransferAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckStorageSharedKeyAccessAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _storageSharedKeyAccessRule
                    .CheckStorageSharedKeyAccessAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckSqlFirewallAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _sqlFirewallRule
                    .CheckSqlFirewallAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckSqlEncryptionAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _sqlEncryptionRule
                    .CheckSqlEncryptionAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckSqlPrivateEndpointAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _sqlPrivateEndpointRule
                    .CheckSqlPrivateEndpointAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckStorageSharedAccessSignatureExpiryAsync(
        string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var findings =
            new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _storageSharedAccessSignatureExpiryRule
                    .CheckStorageSharedAccessSignatureExpiryAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<UniversalResultDto>> ScanAsync(
    string entraTenantId)
    {
        var resources =
            await _discoveryService
                .DiscoverResourcesAsync(entraTenantId);

        var results =
            new List<UniversalResultDto>();

        foreach (var resource in resources)
        {
            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StoragePublicBlob",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storagePublicBlobRule
                        .CheckStoragePublicBlobAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageSecureTransfer",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageSecureTransferRule
                        .CheckStorageSecureTransferAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageSharedKeyAccess",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageSharedKeyAccessRule
                        .CheckStorageSharedKeyAccessAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlFirewall",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlFirewallRule
                        .CheckSqlFirewallAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlEncryption",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlEncryptionRule
                        .CheckSqlEncryptionAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlPrivateEndpoint",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlPrivateEndpointRule
                        .CheckSqlPrivateEndpointAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageSharedAccessSignatureExpiry",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageSharedAccessSignatureExpiryRule
                        .CheckStorageSharedAccessSignatureExpiryAsync(resource)));
        }

        return results;
    }
}