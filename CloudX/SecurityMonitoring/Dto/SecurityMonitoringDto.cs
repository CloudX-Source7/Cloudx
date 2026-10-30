namespace CloudX.SecurityMonitoring.Dto;

public class SecurityFindingDto
{
    public string ResourceId { get; set; } = string.Empty;

    public string ResourceName { get; set; } = string.Empty;

    public string ResourceType { get; set; } = string.Empty;

    public string Category { get; set; } = string.Empty;

    public string Rule { get; set; } = string.Empty;

    public string Severity { get; set; } = string.Empty;

    public string Title { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string Recommendation { get; set; } = string.Empty;

    public string ConfigurationVersion { get; set; } = string.Empty;

    public DateTime DetectedAt { get; set; }
}