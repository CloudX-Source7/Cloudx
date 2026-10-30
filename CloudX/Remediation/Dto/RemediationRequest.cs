
using CloudX.SecurityMonitoring.Dto;

namespace CloudX.Remediation.Dto;

public sealed class RemediationRequest
{
    public SecurityFindingDto Finding { get; set; } = null!;

    public Dictionary<string, string> Parameters { get; set; } = [];
}
