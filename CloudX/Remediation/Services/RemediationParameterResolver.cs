
using CloudX.Remediation.Models;
using CloudX.SecurityMonitoring.Dto;

namespace CloudX.Remediation.Services;

public sealed class RemediationParameterResolver
{
    public Dictionary<string, string> Resolve(
        RemediationCatalogEntry entry,
        SecurityFindingDto finding,
        Dictionary<string, string> suppliedParameters)
    {
        var parameters = new Dictionary<string, string>(
            suppliedParameters,
            StringComparer.OrdinalIgnoreCase);

        // Resource name from the selected finding.
        if (!string.IsNullOrWhiteSpace(finding.ResourceName))
        {
            parameters.TryAdd("resourceName", finding.ResourceName);
        }

        // Resource group from the Azure Resource ID.
        var resourceParts = finding.ResourceId
            .Split('/', StringSplitOptions.RemoveEmptyEntries);

        var resourceGroupIndex = Array.FindIndex(
            resourceParts,
            part => string.Equals(
                part,
                "resourceGroups",
                StringComparison.OrdinalIgnoreCase));

        if (resourceGroupIndex >= 0 &&
            resourceGroupIndex + 1 < resourceParts.Length)
        {
            parameters.TryAdd(
                "resourceGroup",
                resourceParts[resourceGroupIndex + 1]);
        }

        // Map resource-specific parameter names.
        var resourceType = finding.ResourceType;

        if (string.Equals(
                resourceType,
                "Microsoft.Sql/servers",
                StringComparison.OrdinalIgnoreCase))
        {
            parameters.TryAdd("serverName", finding.ResourceName);
        }

        if (string.Equals(
                resourceType,
                "Microsoft.Storage/storageAccounts",
                StringComparison.OrdinalIgnoreCase))
        {
            parameters.TryAdd("accountName", finding.ResourceName);
        }

        if (string.Equals(
                resourceType,
                "Microsoft.KeyVault/vaults",
                StringComparison.OrdinalIgnoreCase))
        {
            parameters.TryAdd("vaultName", finding.ResourceName);
        }

        if (string.Equals(
                resourceType,
                "Microsoft.Web/sites",
                StringComparison.OrdinalIgnoreCase))
        {
            parameters.TryAdd("appName", finding.ResourceName);
        }

        return parameters;
    }
}
