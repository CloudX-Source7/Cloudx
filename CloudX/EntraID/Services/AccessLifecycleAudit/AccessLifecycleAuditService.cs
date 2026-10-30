using AuditModel =
    CloudX.EntraID.Models.AccessLifecycleAudit;

using CloudX.Data;
using Microsoft.EntityFrameworkCore;

namespace CloudX.EntraID.Services.AccessLifecycleAudit;

public class AccessLifecycleAuditService
    : IAccessLifecycleAuditService
{
    private readonly CloudDbContext _dbContext;

    public AccessLifecycleAuditService(
        CloudDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task RecordAsync(
        string action,
        string result,
        int? actorUserId,
        string actorName,
        string entraTenantId,
        string targetUserId,
        string targetDisplayName,
        string targetUserPrincipalName,
        string details)
    {
        var audit = new AuditModel
        {
            TimestampUtc = DateTime.UtcNow,

            Action = action,

            Result = result,

            ActorUserId = actorUserId,

            ActorName = actorName,

            EntraTenantId = entraTenantId,

            TargetUserId = targetUserId,

            TargetDisplayName = targetDisplayName,

            TargetUserPrincipalName =
                targetUserPrincipalName,

            Details = details
        };

        _dbContext.AccessLifecycleAudits.Add(audit);

        await _dbContext.SaveChangesAsync();
    }

    public async Task<List<AuditModel>>
        GetAuditTrailAsync()
    {
        return await _dbContext
            .AccessLifecycleAudits
            .AsNoTracking()
            .OrderByDescending(x => x.TimestampUtc)
            .ToListAsync();
    }
}