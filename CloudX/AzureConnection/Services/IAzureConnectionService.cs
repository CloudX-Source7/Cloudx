
using CloudX.Models;
using AzureConnectionModel = CloudX.Models.AzureConnection;

namespace CloudX.AzureConnection.Services;

public interface IAzureConnectionService
{
    Task<Customer> ConnectAsync(
        int userId,
        string tenantId,
        string customerName,
        string subscriptionId);

    Task<List<AzureConnectionModel>> GetConnectionsAsync(int userId);
}
