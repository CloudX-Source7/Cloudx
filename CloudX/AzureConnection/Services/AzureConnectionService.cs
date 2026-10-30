
using CloudX.Models;
using CloudX.AzureConnection.Repositories;
using AzureConnectionModel = CloudX.Models.AzureConnection;

namespace CloudX.AzureConnection.Services;

public sealed class AzureConnectionService : IAzureConnectionService
{
    private readonly IAzureConnectionRepository _repository;

    public AzureConnectionService(
        IAzureConnectionRepository repository)
    {
        _repository = repository;
    }

    public async Task<Customer> ConnectAsync(
        int userId,
        string tenantId,
        string customerName,
        string subscriptionId)
    {
        if (userId <= 0)
            throw new ArgumentException("Invalid user ID.", nameof(userId));

        if (string.IsNullOrWhiteSpace(tenantId))
            throw new ArgumentException("Tenant ID is required.", nameof(tenantId));

        if (string.IsNullOrWhiteSpace(subscriptionId))
            throw new ArgumentException(
                "Subscription ID is required.", nameof(subscriptionId));

        tenantId = tenantId.Trim();
        subscriptionId = subscriptionId.Trim();

        customerName = string.IsNullOrWhiteSpace(customerName)
            ? "Azure Customer"
            : customerName.Trim();

        var customer = await _repository
            .GetCustomerByTenantIdAsync(tenantId);

        if (customer is null)
        {
            customer = await _repository.CreateCustomerAsync(
                userId,
                tenantId,
                customerName);
        }
        else if (customer.UserId != userId)
        {
            throw new UnauthorizedAccessException(
                "This Azure tenant is already connected to another user.");
        }

        var exists = await _repository.ConnectionExistsAsync(
            customer.Id,
            subscriptionId);

        if (!exists)
        {
            await _repository.CreateConnectionAsync(
                customer.Id,
                subscriptionId);
        }

        return customer;
    }

    public async Task<List<AzureConnectionModel>> GetConnectionsAsync(
        int userId)
    {
        if (userId <= 0)
            throw new ArgumentException("Invalid user ID.", nameof(userId));

        return await _repository.GetConnectionsByUserIdAsync(userId);
    }
}
