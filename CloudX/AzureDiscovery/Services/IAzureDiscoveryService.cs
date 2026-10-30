
using CloudX.AzureDiscovery.Dto;

namespace CloudX.AzureDiscovery.Services;

public interface IAzureDiscoveryService
{
    Task<IReadOnlyList<ResourceDto>> DiscoverResourcesAsync(
        string entraTenantId);

    Task<IReadOnlyList<ResourceDto>> DiscoverResourcesAsync(
        string entraTenantId,
        string subscriptionId);
}
