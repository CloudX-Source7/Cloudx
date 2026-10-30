namespace CloudX.EntraID.DTOs;

public class ExcessivePrivilegeDto
{
    public string UserId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public string UserType { get; set; } = string.Empty;

    public bool? AccountEnabled { get; set; }

    public int PrivilegedRoleCount { get; set; }

    public string PrivilegedRoles { get; set; } = string.Empty;

    public string DetectionRule { get; set; } = string.Empty;

    public string DetectionReason { get; set; } = string.Empty;
}