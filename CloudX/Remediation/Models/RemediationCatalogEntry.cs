
namespace CloudX.Remediation.Models;

public sealed class RemediationCatalogEntry
{
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public List<string> SupportedRuleIds { get; set; } = [];

    public List<string> ResourceTypes { get; set; } = [];

    public string Description { get; set; } = string.Empty;

    public string CommandTemplate { get; set; } = string.Empty;

    public List<string> RequiredParameters { get; set; } = [];

    public string ImpactWarning { get; set; } = string.Empty;

    public bool RequiresApproval { get; set; } = true;
}
