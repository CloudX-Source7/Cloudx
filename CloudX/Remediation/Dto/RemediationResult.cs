
namespace CloudX.Remediation.Dto;

public sealed class RemediationResult
{
    public bool Success { get; set; }

    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string ImpactWarning { get; set; } = string.Empty;

    public bool RequiresApproval { get; set; }

    public string Message { get; set; } = string.Empty;

    public string CommandTemplate { get; set; } = string.Empty;

    public string Command { get; set; } = string.Empty;

    public List<string> MissingParameters { get; set; } = [];
}
