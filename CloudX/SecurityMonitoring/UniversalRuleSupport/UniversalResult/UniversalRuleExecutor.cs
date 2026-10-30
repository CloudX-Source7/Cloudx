using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.UniversalRuleSupport;

public static class UniversalRuleExecutor
{
    public static async Task<UniversalResultDto> ExecuteAsync(
        string rule,
        string resourceId,
        string resourceName,
        string resourceType,
        Func<Task<SecurityFindingDto?>> ruleAction)
    {
        try
        {
            var finding = await ruleAction();

            // Risk found
            if (finding != null)
            {
                return new UniversalResultDto
                {
                    Status = "Risk",
                    Rule = rule,
                    ResourceId = resourceId,
                    ResourceName = resourceName,
                    ResourceType = resourceType,
                    Finding = finding,
                    DetectedAt = DateTime.UtcNow
                };
            }

            // No risk
            return new UniversalResultDto
            {
                Status = "NoRisk",
                Rule = rule,
                ResourceId = resourceId,
                ResourceName = resourceName,
                ResourceType = resourceType,
                DetectedAt = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            // Log the actual exception for debugging.
            Console.Error.WriteLine(
                $"[CloudX Scan] Rule: {rule} | Resource: {resourceId}");

            Console.Error.WriteLine(ex.ToString());

            var reason = GetFriendlyErrorMessage(ex);

            return UniversalResult.NotEvaluated(
                rule,
                resourceId,
                resourceName,
                resourceType,
                reason);
        }
    }

    private static string GetFriendlyErrorMessage(Exception ex)
    {
        var message = ex.ToString();

        // Azure authorization failure
        if (message.Contains("403") ||
            message.Contains("AuthorizationFailed",
                StringComparison.OrdinalIgnoreCase) ||
            message.Contains("Forbidden",
                StringComparison.OrdinalIgnoreCase))
        {
            return "CloudX couldn't evaluate this security check because the connected Azure identity does not have sufficient permissions.";
        }

        // Azure authentication failure
        if (message.Contains("401") ||
            message.Contains("Unauthorized",
                StringComparison.OrdinalIgnoreCase) ||
            message.Contains("AuthenticationFailed",
                StringComparison.OrdinalIgnoreCase))
        {
            return "CloudX couldn't evaluate this security check because Azure authentication failed.";
        }

        // Resource not found
        if (message.Contains("404") ||
            message.Contains("NotFound",
                StringComparison.OrdinalIgnoreCase) ||
            message.Contains("ResourceNotFound",
                StringComparison.OrdinalIgnoreCase))
        {
            return "CloudX couldn't evaluate this security check because the required Azure resource could not be found.";
        }

        // Azure throttling
        if (message.Contains("429") ||
            message.Contains("TooManyRequests",
                StringComparison.OrdinalIgnoreCase) ||
            message.Contains("throttl",
                StringComparison.OrdinalIgnoreCase))
        {
            return "CloudX couldn't complete this security check because Azure temporarily limited requests. Please run the scan again later.";
        }

        // Timeout
        if (ex is TimeoutException ||
            message.Contains("timeout",
                StringComparison.OrdinalIgnoreCase) ||
            message.Contains("timed out",
                StringComparison.OrdinalIgnoreCase))
        {
            return "CloudX couldn't complete this security check because the Azure request timed out. Please run the scan again.";
        }

        // General failure
        return "CloudX couldn't complete this security check. Please try running the scan again.";
    }
}