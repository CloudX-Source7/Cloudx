using CloudX.SecurityMonitoring.Dto;

namespace CloudX.SecurityMonitoring.UniversalRuleSupport;

public class UniversalResultDto
{
    public string Status { get; set; } = string.Empty;

    public string Rule { get; set; } = string.Empty;

    public string ResourceId { get; set; } = string.Empty;

    public string ResourceName { get; set; } = string.Empty;

    public string ResourceType { get; set; } = string.Empty;

    public SecurityFindingDto? Finding { get; set; }

    public string Reason { get; set; } = string.Empty;

    public DateTime DetectedAt { get; set; }
}