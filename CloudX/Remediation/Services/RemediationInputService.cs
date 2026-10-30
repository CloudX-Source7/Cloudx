
using CloudX.Remediation.Dto;

namespace CloudX.Remediation.Services;

public sealed class RemediationInputService
{
    public string? Validate(RemediationRequest? request)
    {
        if (request is null)
            return "Remediation request is missing.";

        if (request.Finding is null)
            return "Selected security finding is missing.";

        var finding = request.Finding;

        if (string.IsNullOrWhiteSpace(finding.ResourceId))
            return "Finding resource ID is missing.";

        if (string.IsNullOrWhiteSpace(finding.ResourceName))
            return "Finding resource name is missing.";

        if (string.IsNullOrWhiteSpace(finding.ResourceType))
            return "Finding resource type is missing.";

        if (string.IsNullOrWhiteSpace(finding.Rule))
            return "Finding rule ID is missing.";

        if (request.Parameters is null)
            return "Remediation parameters are missing.";

        return null;
    }
}
