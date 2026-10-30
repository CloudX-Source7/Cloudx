using CloudX.AzureDiscovery.Services;
using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.Rules.Misconfiguration;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services;

public class MisconfigurationService : IMisconfigurationService
{
    private readonly IAzureDiscoveryService _discoveryService;

    private readonly WebAppHttpsOnlyRule _webAppHttpsOnlyRule;
    private readonly WebAppAuthenticationRule _webAppAuthenticationRule;
    private readonly WebAppManagedIdentityRule _webAppManagedIdentityRule;
    private readonly WebAppRemoteDebuggingRule _webAppRemoteDebuggingRule;
    private readonly WebAppBasicAuthenticationRule _webAppBasicAuthenticationRule;
    private readonly WebAppCorsRule _webAppCorsRule;
    private readonly WebAppFtpStateRule _webAppFtpStateRule;
    private readonly WebAppLoggingRule _webAppLoggingRule;
    private readonly SqlPublicNetworkRule _sqlPublicNetworkRule;
    private readonly SqlFirewallRule _sqlFirewallRule;
    private readonly SqlTlsRule _sqlTlsRule;
    private readonly StoragePublicAccessRule _storagePublicAccessRule;
    private readonly StorageSecureTransferRule _storageSecureTransferRule;
    private readonly StorageNetworkRule _storageNetworkRule;
    private readonly KeyVaultPublicNetworkRule _keyVaultPublicNetworkRule;
    private readonly KeyVaultSoftDeleteRule _keyVaultSoftDeleteRule;
    private readonly KeyVaultPurgeProtectionRule _keyVaultPurgeProtectionRule;
    private readonly ActivityLogAlertMissingRule _activityLogAlertMissingRule;

    public MisconfigurationService(
        IAzureDiscoveryService discoveryService,
        WebAppHttpsOnlyRule webAppHttpsOnlyRule,
        WebAppAuthenticationRule webAppAuthenticationRule,
        WebAppManagedIdentityRule webAppManagedIdentityRule,
        WebAppRemoteDebuggingRule webAppRemoteDebuggingRule,
        WebAppBasicAuthenticationRule webAppBasicAuthenticationRule,
        WebAppCorsRule webAppCorsRule,
        WebAppFtpStateRule webAppFtpStateRule,
        WebAppLoggingRule webAppLoggingRule,
        SqlPublicNetworkRule sqlPublicNetworkRule,
        SqlFirewallRule sqlFirewallRule,
        SqlTlsRule sqlTlsRule,
        StoragePublicAccessRule storagePublicAccessRule,
        StorageSecureTransferRule storageSecureTransferRule,
        StorageNetworkRule storageNetworkRule,
        KeyVaultPublicNetworkRule keyVaultPublicNetworkRule,
        KeyVaultSoftDeleteRule keyVaultSoftDeleteRule,
        KeyVaultPurgeProtectionRule keyVaultPurgeProtectionRule,
        ActivityLogAlertMissingRule activityLogAlertMissingRule)
    {
        _discoveryService = discoveryService;
        _webAppHttpsOnlyRule = webAppHttpsOnlyRule;
        _webAppAuthenticationRule = webAppAuthenticationRule;
        _webAppManagedIdentityRule = webAppManagedIdentityRule;
        _webAppRemoteDebuggingRule = webAppRemoteDebuggingRule;
        _webAppBasicAuthenticationRule = webAppBasicAuthenticationRule;
        _webAppCorsRule = webAppCorsRule;
        _webAppFtpStateRule = webAppFtpStateRule;
        _webAppLoggingRule = webAppLoggingRule;
        _sqlPublicNetworkRule = sqlPublicNetworkRule;
        _sqlFirewallRule = sqlFirewallRule;
        _sqlTlsRule = sqlTlsRule;
        _storagePublicAccessRule = storagePublicAccessRule;
        _storageSecureTransferRule = storageSecureTransferRule;
        _storageNetworkRule = storageNetworkRule;
        _keyVaultPublicNetworkRule = keyVaultPublicNetworkRule;
        _keyVaultSoftDeleteRule = keyVaultSoftDeleteRule;
        _keyVaultPurgeProtectionRule = keyVaultPurgeProtectionRule;
        _activityLogAlertMissingRule = activityLogAlertMissingRule;

    }

    public async Task<List<SecurityFindingDto>> CheckWebAppHttpsOnlyAsync(
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
                await _webAppHttpsOnlyRule
                    .CheckWebAppHttpsOnlyAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }

    public async Task<List<SecurityFindingDto>> CheckWebAppAuthenticationAsync(
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

    public async Task<List<SecurityFindingDto>> CheckWebAppManagedIdentityAsync(
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
    public async Task<List<SecurityFindingDto>> CheckWebAppRemoteDebuggingAsync(
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
                await _webAppRemoteDebuggingRule
                    .CheckWebAppRemoteDebuggingAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckWebAppBasicAuthenticationAsync(
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
                await _webAppBasicAuthenticationRule
                    .CheckWebAppBasicAuthenticationAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckWebAppCorsAsync(
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
                await _webAppCorsRule
                    .CheckWebAppCorsAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckWebAppFtpStateAsync(
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
                await _webAppFtpStateRule
                    .CheckWebAppFtpStateAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckWebAppLoggingAsync(
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
                await _webAppLoggingRule
                    .CheckWebAppLoggingAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckSqlPublicNetworkAsync(
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
    public async Task<List<SecurityFindingDto>> CheckSqlFirewallRuleAsync(
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
                    .CheckSqlFirewallRuleAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckSqlTlsAsync(
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
                await _sqlTlsRule
                    .CheckSqlTlsAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckStoragePublicAccessAsync(
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
                await _storagePublicAccessRule
                    .CheckStoragePublicAccessAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckStorageSecureTransferAsync(
    string entraTenantId)
    {
        var resources =
    await _discoveryService.DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _storageSecureTransferRule.CheckStorageSecureTransferAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckStorageNetworkAsync(
    string entraTenantId)
    {
        var resources =
            await _discoveryService.DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

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
    public async Task<List<SecurityFindingDto>> CheckKeyVaultPublicNetworkAsync(
    string entraTenantId)
    {
        var resources =
            await _discoveryService.DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

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
    public async Task<List<SecurityFindingDto>> CheckKeyVaultSoftDeleteAsync(
    string entraTenantId)
    {
        var resources =
            await _discoveryService.DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _keyVaultSoftDeleteRule
                    .CheckKeyVaultSoftDeleteAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckKeyVaultPurgeProtectionAsync(
    string entraTenantId)
    {
        var resources =
            await _discoveryService.DiscoverResourcesAsync(entraTenantId);

        var findings = new List<SecurityFindingDto>();

        foreach (var resource in resources)
        {
            var finding =
                await _keyVaultPurgeProtectionRule
                    .CheckKeyVaultPurgeProtectionAsync(resource);

            if (finding != null)
            {
                findings.Add(finding);
            }
        }

        return findings;
    }
    public async Task<List<SecurityFindingDto>> CheckActivityLogAlertMissingAsync(
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
                await _activityLogAlertMissingRule
                    .CheckActivityLogAlertMissingAsync(resource);

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
                    "WebAppHttpsOnly",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppHttpsOnlyRule
                        .CheckWebAppHttpsOnlyAsync(resource)));

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
                    "WebAppManagedIdentity",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppManagedIdentityRule
                        .CheckWebAppManagedIdentityAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppRemoteDebugging",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppRemoteDebuggingRule
                        .CheckWebAppRemoteDebuggingAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppBasicAuthentication",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppBasicAuthenticationRule
                        .CheckWebAppBasicAuthenticationAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppCors",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppCorsRule
                        .CheckWebAppCorsAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppFtpState",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppFtpStateRule
                        .CheckWebAppFtpStateAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "WebAppLogging",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _webAppLoggingRule
                        .CheckWebAppLoggingAsync(resource)));

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
                    "SqlFirewallRule",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlFirewallRule
                        .CheckSqlFirewallRuleAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "SqlTls",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _sqlTlsRule
                        .CheckSqlTlsAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "StoragePublicAccess",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storagePublicAccessRule
                        .CheckStoragePublicAccessAsync(resource)));

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
                    "StorageNetwork",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _storageNetworkRule
                        .CheckStorageNetworkAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultPublicNetwork",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultPublicNetworkRule
                        .CheckKeyVaultPublicNetworkAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultSoftDelete",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultSoftDeleteRule
                        .CheckKeyVaultSoftDeleteAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "KeyVaultPurgeProtection",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _keyVaultPurgeProtectionRule
                        .CheckKeyVaultPurgeProtectionAsync(resource)));

            results.Add(
                await UniversalRuleExecutor.ExecuteAsync(
                    "ActivityLogAlertMissing",
                    resource.Id,
                    resource.Name,
                    resource.Type,
                    () => _activityLogAlertMissingRule
                        .CheckActivityLogAlertMissingAsync(resource)));
        }

        return results;
    }
}