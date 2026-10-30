using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.NetworkFirewall;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.NetworkFirewall;

public class NetworkFirewallService : INetworkFirewallService
{
    private readonly IAzureDiscoveryService _discoveryService;

    private readonly SqlFirewallRule _sqlFirewallRule;
    private readonly SqlPublicNetworkRule _sqlPublicNetworkRule;
    private readonly StorageNetworkRule _storageNetworkRule;
    private readonly KeyVaultFirewallRule _keyVaultFirewallRule;
    private readonly NsgOpenInternetRule _nsgOpenInternetRule;
    private readonly NsgBroadInboundRule _nsgBroadInboundRule;
    private readonly SubnetMissingNsgRule _subnetMissingNsgRule;

    public NetworkFirewallService(
        IAzureDiscoveryService discoveryService,
        SqlFirewallRule sqlFirewallRule,
        SqlPublicNetworkRule sqlPublicNetworkRule,
        StorageNetworkRule storageNetworkRule,
        KeyVaultFirewallRule keyVaultFirewallRule,
        NsgOpenInternetRule nsgOpenInternetRule,
        NsgBroadInboundRule nsgBroadInboundRule,
        SubnetMissingNsgRule subnetMissingNsgRule)
    {
        _discoveryService = discoveryService;

        _sqlFirewallRule = sqlFirewallRule;
        _sqlPublicNetworkRule = sqlPublicNetworkRule;
        _storageNetworkRule = storageNetworkRule;
        _keyVaultFirewallRule = keyVaultFirewallRule;
        _nsgOpenInternetRule = nsgOpenInternetRule;
        _nsgBroadInboundRule = nsgBroadInboundRule;
        _subnetMissingNsgRule = subnetMissingNsgRule;
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
        CheckSqlPublicNetworkAsync(
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
                await _sqlPublicNetworkRule
                    .CheckSqlPublicNetworkAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckStorageNetworkAsync(
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
                await _storageNetworkRule
                    .CheckStorageNetworkAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>>
        CheckKeyVaultFirewallAsync(
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
                await _keyVaultFirewallRule
                    .CheckKeyVaultFirewallAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckNsgOpenInternetAsync(
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
                await _nsgOpenInternetRule
                    .CheckNsgOpenInternetAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckNsgBroadInboundAsync(
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
                await _nsgBroadInboundRule
                    .CheckNsgBroadInboundAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>>
    CheckSubnetMissingNsgAsync(
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
                await _subnetMissingNsgRule
                    .CheckSubnetMissingNsgAsync(resource);

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
                    "SqlFirewall",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlFirewallRule
                        .CheckSqlFirewallAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlPublicNetwork",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlPublicNetworkRule
                        .CheckSqlPublicNetworkAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StorageNetwork",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageNetworkRule
                        .CheckStorageNetworkAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultFirewall",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultFirewallRule
                        .CheckKeyVaultFirewallAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "NsgOpenInternet",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _nsgOpenInternetRule
                        .CheckNsgOpenInternetAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "NsgBroadInbound",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _nsgBroadInboundRule
                        .CheckNsgBroadInboundAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SubnetMissingNsg",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _subnetMissingNsgRule
                        .CheckSubnetMissingNsgAsync(resource)));
        }

        return results;
    }
}