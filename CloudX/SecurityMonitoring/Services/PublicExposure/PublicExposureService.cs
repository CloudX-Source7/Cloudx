using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.PublicExposure;
using CloudX.SecurityMonitoring.Services.PublicExposure;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services;

public class PublicExposureService : IPublicExposureService
{
    private readonly IAzureDiscoveryService _discoveryService;
    private readonly WebAppPublicAccessRule _webAppPublicAccessRule;
    private readonly SqlPublicAccessRule _sqlPublicAccessRule;
    private readonly StoragePublicBlobRule _storagePublicBlobRule;
    private readonly KeyVaultPublicNetworkRule _keyVaultPublicNetworkRule;
    



    public PublicExposureService(
        IAzureDiscoveryService discoveryService,
        WebAppPublicAccessRule webAppPublicAccessRule,
        SqlPublicAccessRule sqlPublicAccessRule,
        StoragePublicBlobRule storagePublicBlobRule,
        KeyVaultPublicNetworkRule keyVaultPublicNetworkRule)
    {
        _discoveryService = discoveryService;
        _webAppPublicAccessRule = webAppPublicAccessRule;
        _sqlPublicAccessRule = sqlPublicAccessRule;
        _storagePublicBlobRule = storagePublicBlobRule;
        _keyVaultPublicNetworkRule = keyVaultPublicNetworkRule;
    }

    public async Task<List<SecurityFindingDto>>
        CheckWebAppPublicAccessAsync(
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
                await _webAppPublicAccessRule
                    .CheckWebAppPublicAccessAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
       CheckSqlPublicAccessAsync(
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
                await _sqlPublicAccessRule
                    .CheckSqlPublicAccessAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
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
    CheckKeyVaultPublicNetworkAsync(
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
                await _keyVaultPublicNetworkRule
                    .CheckKeyVaultPublicNetworkAsync(resource);

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
                    "WebAppPublicAccess",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppPublicAccessRule
                        .CheckWebAppPublicAccessAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlPublicAccess",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlPublicAccessRule
                        .CheckSqlPublicAccessAsync(resource)));

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
                    "KeyVaultPublicNetwork",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultPublicNetworkRule
                        .CheckKeyVaultPublicNetworkAsync(resource)));
        }

        return results;
    }
}