namespace CloudX.Models;

public class AzureConnection
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public string SubscriptionId { get; set; } = null!;

    public DateTime ConnectedAt { get; set; }

    public Customer Customer { get; set; } = null!;
}