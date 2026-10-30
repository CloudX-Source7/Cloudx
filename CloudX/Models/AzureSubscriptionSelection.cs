
namespace CloudX.Models;

public class AzureSubscriptionSelection
{
    public int Id { get; set; }

    public int CustomerId { get; set; }

    public string SubscriptionId { get; set; } = null!;

    public DateTime SelectedAt { get; set; }

    public Customer Customer { get; set; } = null!;
}
