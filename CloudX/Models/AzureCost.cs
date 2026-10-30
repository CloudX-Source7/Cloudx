namespace CloudX.Models;

public class AzureCost
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public string AzureResourceId { get; set; } = null!;

    public string ResourceName { get; set; } = null!;

    public string ResourceType { get; set; } = null!;

    public decimal Cost { get; set; }

    public string Currency { get; set; } = null!;

    public DateTime Date { get; set; }

    public DateTime LastUpdatedAt { get; set; }

    public Customer Customer { get; set; } = null!;
}