using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.IdentityAccess;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.IdentityAccess;

public class IdentityAccessService : IIdentityAccessService
{
    private readonly IAzureDiscoveryService _discoveryService;

    private readonly WebAppManagedIdentityRule _webAppManagedIdentityRule;

    private readonly WebAppAuthenticationRule _webAppAuthenticationRule;
    
    private readonly KeyVaultAccessPolicyRule _keyVaultAccessPolicyRule;
    private readonly KeyVaultRbacRule _keyVaultRbacRule;
    private readonly StorageRbacRule _storageRbacRule;
    private readonly SqlAuthenticationRule _sqlAuthenticationRule;





    public IdentityAccessService(
        IAzureDiscoveryService discoveryService,
        WebAppManagedIdentityRule webAppManagedIdentityRule,
        WebAppAuthenticationRule webAppAuthenticationRule,
        KeyVaultAccessPolicyRule keyVaultAccessPolicyRule,
        KeyVaultRbacRule keyVaultRbacRule,
        StorageRbacRule storageRbacRule,
        SqlAuthenticationRule sqlAuthenticationRule)
    {
        _discoveryService = discoveryService;
        _webAppManagedIdentityRule = webAppManagedIdentityRule;
        _webAppAuthenticationRule = webAppAuthenticationRule;
        _keyVaultAccessPolicyRule = keyVaultAccessPolicyRule;
        _keyVaultRbacRule = keyVaultRbacRule;
        _storageRbacRule = storageRbacRule;
        _sqlAuthenticationRule = sqlAuthenticationRule;
    }

    public async Task<List<SecurityFindingDto>>
        CheckWebAppManagedIdentityAsync(
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
                await _webAppManagedIdentityRule
                    .CheckWebAppManagedIdentityAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckWebAppAuthenticationAsync(
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
                await _webAppAuthenticationRule
                    .CheckWebAppAuthenticationAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckKeyVaultAccessPolicyAsync(
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
                await _keyVaultAccessPolicyRule
                    .CheckKeyVaultAccessPolicyAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckKeyVaultRbacAsync(
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
                await _keyVaultRbacRule
                    .CheckKeyVaultRbacAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckStorageRbacAsync(
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
                await _storageRbacRule
                    .CheckStorageRbacAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckSqlAuthenticationAsync(
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
                await _sqlAuthenticationRule
                    .CheckSqlAuthenticationAsync(resource);

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
                    "WebAppManagedIdentity",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppManagedIdentityRule
                        .CheckWebAppManagedIdentityAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppAuthentication",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppAuthenticationRule
                        .CheckWebAppAuthenticationAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultAccessPolicy",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultAccessPolicyRule
                        .CheckKeyVaultAccessPolicyAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultRbac",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultRbacRule
                        .CheckKeyVaultRbacAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageRbac",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageRbacRule
                        .CheckStorageRbacAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlAuthentication",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlAuthenticationRule
                        .CheckSqlAuthenticationAsync(resource)));
        }

        return results;
    }
}