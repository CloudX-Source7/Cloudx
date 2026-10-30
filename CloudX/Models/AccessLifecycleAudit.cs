namespace CloudX.EntraID.Models;

public class AccessLifecycleAudit
{
    public int Id { get; set; }

    public DateTime TimestampUtc { get; set; }

    public string Action { get; set; } = string.Empty;

    public string Result { get; set; } = string.Empty;

    public int? ActorUserId { get; set; }

    public string ActorName { get; set; } = string.Empty;

    public string EntraTenantId { get; set; } = string.Empty;

    public string TargetUserId { get; set; } = string.Empty;

    public string TargetDisplayName { get; set; } = string.Empty;

    public string TargetUserPrincipalName { get; set; } = string.Empty;

    public string Details { get; set; } = string.Empty;
}