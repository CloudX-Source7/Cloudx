namespace CloudX.EntraID.DTOs;

public class PrivilegedAccountDto
{
    public string UserId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public string UserType { get; set; } = string.Empty;

    public bool? AccountEnabled { get; set; }

    public string RoleName { get; set; } = string.Empty;

    public string RoleDefinitionId { get; set; } = string.Empty;

    public string DirectoryScope { get; set; } = string.Empty;

    public string DetectionReason { get; set; } = string.Empty;
}