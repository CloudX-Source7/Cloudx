
using CloudX.Data;
using CloudX.Models;
using Microsoft.EntityFrameworkCore;
using AzureConnectionModel = CloudX.Models.AzureConnection;

namespace CloudX.AzureConnection.Repositories;

public sealed class AzureConnectionRepository : IAzureConnectionRepository
{
    private readonly CloudDbContext _db;

    public AzureConnectionRepository(CloudDbContext db)
    {
        _db = db;
    }

    public async Task<Customer?> GetCustomerByTenantIdAsync(
        string tenantId)
    {
        return await _db.Customers
            .SingleOrDefaultAsync(c => c.EntraTenantId == tenantId);
    }

    public async Task<Customer> CreateCustomerAsync(
        int userId,
        string tenantId,
        string customerName)
    {
        var customer = new Customer
        {
            UserId = userId,
            EntraTenantId = tenantId,
            Name = customerName,
            CreatedAt = DateTime.UtcNow
        };

        _db.Customers.Add(customer);
        await _db.SaveChangesAsync();

        return customer;
    }

    public async Task<bool> ConnectionExistsAsync(
        int customerId,
        string subscriptionId)
    {
        return await _db.AzureConnections.AnyAsync(c =>
            c.CustomerId == customerId &&
            c.SubscriptionId == subscriptionId);
    }

    public async Task<AzureConnectionModel> CreateConnectionAsync(
        int customerId,
        string subscriptionId)
    {
        var connection = new AzureConnectionModel
        {
            CustomerId = customerId,
            SubscriptionId = subscriptionId,
            ConnectedAt = DateTime.UtcNow
        };

        _db.AzureConnections.Add(connection);
        await _db.SaveChangesAsync();

        return connection;
    }

    public async Task<List<AzureConnectionModel>> GetConnectionsByUserIdAsync(
        int userId)
    {
        return await _db.AzureConnections
            .AsNoTracking()
            .Where(c => c.Customer.UserId == userId)
            .OrderByDescending(c => c.ConnectedAt)
            .ToListAsync();
    }
}
