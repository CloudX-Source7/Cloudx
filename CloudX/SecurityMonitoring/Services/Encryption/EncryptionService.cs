
using CloudX.AzureDiscovery.Dto;
using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.Encryption;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.Encryption;

public class EncryptionService : IEncryptionService
{
    private readonly IAzureDiscoveryService _discoveryService;
    private readonly StorageEncryptionRule _storageEncryptionRule;
    private readonly StorageCustomerManagedKeyRule _storageCustomerManagedKeyRule;
    private readonly SqlEncryptionRule _sqlEncryptionRule;
    private readonly SqlCustomerManagedKeyRule _sqlCustomerManagedKeyRule;
    private readonly KeyVaultKeyProtectionRule _keyVaultKeyProtectionRule;
    private readonly WebAppTlsRule _webAppTlsRule;

    public EncryptionService(
        IAzureDiscoveryService discoveryService,
        StorageEncryptionRule storageEncryptionRule,
        StorageCustomerManagedKeyRule sqlEncryptionRulePlaceholder,
        SqlEncryptionRule sqlEncryptionRule,
        SqlCustomerManagedKeyRule sqlCustomerManagedKeyRule,
        KeyVaultKeyProtectionRule keyVaultKeyProtectionRule,
        WebAppTlsRule webAppTlsRule)
    {
        _discoveryService = discoveryService;
        _storageEncryptionRule = storageEncryptionRule;
        _storageCustomerManagedKeyRule = sqlEncryptionRulePlaceholder;
        _sqlEncryptionRule = sqlEncryptionRule;
        _sqlCustomerManagedKeyRule = sqlCustomerManagedKeyRule;
        _keyVaultKeyProtectionRule = keyVaultKeyProtectionRule;
        _webAppTlsRule = webAppTlsRule;
    }

    public async Task<List<SecurityFindingDto>>
        CheckStorageEncryptionAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _storageEncryptionRule
                .CheckStorageEncryptionAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckStorageCustomerManagedKeyAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _storageCustomerManagedKeyRule
                .CheckStorageCustomerManagedKeyAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckSqlEncryptionAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _sqlEncryptionRule
                .CheckSqlEncryptionAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckSqlCustomerManagedKeyAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _sqlCustomerManagedKeyRule
                .CheckSqlCustomerManagedKeyAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckKeyVaultKeyProtectionAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _keyVaultKeyProtectionRule
                .CheckKeyVaultKeyProtectionAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckWebAppTlsAsync(string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding = await _webAppTlsRule
                .CheckWebAppTlsAsync(resource);

            if (finding != null)
                findings.Add(finding);
        }

        return findings;
    }

    // Existing tenant-wide scan. Preserved for compatibility.
    public async Task<List<UniversalResultDto>> ScanAsync(
        string entraTenantId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId);

        return await ScanResourcesAsync(resources);
    }

    // New selected-subscription scan.
    public async Task<List<UniversalResultDto>> ScanAsync(
        string entraTenantId,
        string subscriptionId)
    {
        var resources = await _discoveryService
            .DiscoverResourcesAsync(entraTenantId, subscriptionId);

        return await ScanResourcesAsync(resources);
    }

    private async Task<List<UniversalResultDto>> ScanResourcesAsync(
        IReadOnlyList<ResourceDto> resources)
    {
        var results = new List<UniversalResultDto>();

        foreach (var resource in resources)
        {
            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageEncryption",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageEncryptionRule
                        .CheckStorageEncryptionAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageCustomerManagedKey",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageCustomerManagedKeyRule
                        .CheckStorageCustomerManagedKeyAsync(resource)));

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
                    "SqlCustomerManagedKey",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlCustomerManagedKeyRule
                        .CheckSqlCustomerManagedKeyAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultKeyProtection",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultKeyProtectionRule
                        .CheckKeyVaultKeyProtectionAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppTls",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppTlsRule
                        .CheckWebAppTlsAsync(resource)));
        }

        return results;
    }
}
