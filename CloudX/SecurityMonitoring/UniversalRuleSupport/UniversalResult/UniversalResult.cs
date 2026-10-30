namespace CloudX.SecurityMonitoring.UniversalRuleSupport;

public static class UniversalResult
{
    public static UniversalResultDto NotEvaluated(
        string rule,
        string resourceId,
        string resourceName,
        string resourceType,
        string reason)
    {
        return new UniversalResultDto
        {
            Status = "NotEvaluated",

            Rule = rule,

            ResourceId = resourceId,

            ResourceName = resourceName,

            ResourceType = resourceType,

            Reason = reason,

            DetectedAt = DateTime.UtcNow
        };
    }
}