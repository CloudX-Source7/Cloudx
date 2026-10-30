
using CloudX.Models;
using AzureConnectionModel = CloudX.Models.AzureConnection;

namespace CloudX.AzureConnection.Repositories;

public interface IAzureConnectionRepository
{
    Task<Customer?> GetCustomerByTenantIdAsync(string tenantId);

    Task<Customer> CreateCustomerAsync(
        int userId,
        string tenantId,
        string customerName);

    Task<bool> ConnectionExistsAsync(
        int customerId,
        string subscriptionId);

    Task<AzureConnectionModel> CreateConnectionAsync(
        int customerId,
        string subscriptionId);

    Task<List<AzureConnectionModel>> GetConnectionsByUserIdAsync(
        int userId);
}
