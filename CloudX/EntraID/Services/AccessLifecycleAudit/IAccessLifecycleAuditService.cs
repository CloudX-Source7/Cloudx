using AuditModel =
    CloudX.EntraID.Models.AccessLifecycleAudit;

namespace CloudX.EntraID.Services.AccessLifecycleAudit;

public interface IAccessLifecycleAuditService
{
    Task RecordAsync(
        string action,
        string result,
        int? actorUserId,
        string actorName,
        string entraTenantId,
        string targetUserId,
        string targetDisplayName,
        string targetUserPrincipalName,
        string details);

    Task<List<AuditModel>> GetAuditTrailAsync();
}