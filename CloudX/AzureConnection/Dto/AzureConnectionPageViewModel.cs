
using AzureConnectionModel = CloudX.Models.AzureConnection;

namespace CloudX.AzureConnection.DTOs;

public sealed class AzureConnectionPageViewModel
{
    public bool IsAzureAuthorized { get; set; }

    public string? TenantId { get; set; }

    public List<AzureConnectionModel> Connections { get; set; } = new();
}
