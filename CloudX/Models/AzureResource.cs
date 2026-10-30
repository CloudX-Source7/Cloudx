namespace CloudX.Models;

public class AzureResource
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public string AzureResourceId { get; set; } = null!;

    public string Name { get; set; } = null!;

    public string Type { get; set; } = null!;

    public string Location { get; set; } = null!;

    public string ResourceGroup { get; set; } = null!;

    public string SubscriptionId { get; set; } = null!;

    public DateTime LastDiscoveredAt { get; set; }

    public Customer Customer { get; set; } = null!;
}