namespace CloudX.Models;

public class Customer
{
    public int Id { get; set; }

    public int UserId { get; set; }

    public User User { get; set; } = null!;

    public string EntraTenantId { get; set; } = null!;

    public string Name { get; set; } = null!;

    public DateTime CreatedAt { get; set; }

    public ICollection<AzureConnection> AzureConnections { get; set; }
        = new List<AzureConnection>();
}