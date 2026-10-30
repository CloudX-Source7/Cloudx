
using CloudX.Remediation.Models;
using CloudX.SecurityMonitoring.Dto;

namespace CloudX.Remediation.Services;

public sealed class RemediationCatalogMatcher
{
    private readonly IReadOnlyList<RemediationCatalogEntry> _catalog;

    public RemediationCatalogMatcher(
        IReadOnlyList<RemediationCatalogEntry> catalog)
    {
        _catalog = catalog;
    }

    public RemediationCatalogEntry? Match(
        SecurityFindingDto finding)
    {
        var matches = _catalog
            .Where(entry =>
                entry.SupportedRuleIds.Any(rule =>
                    string.Equals(
                        rule,
                        finding.Rule,
                        StringComparison.OrdinalIgnoreCase))
                &&
                entry.ResourceTypes.Any(type =>
                    string.Equals(
                        type,
                        finding.ResourceType,
                        StringComparison.OrdinalIgnoreCase)))
            .ToList();

        if (matches.Count > 1)
        {
            throw new InvalidOperationException(
                $"Multiple remediation catalog entries match rule '{finding.Rule}'.");
        }

        return matches.SingleOrDefault();
    }
}
