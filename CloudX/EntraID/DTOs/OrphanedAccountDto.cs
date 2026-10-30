namespace CloudX.EntraID.DTOs;

public class OrphanedAccountDto
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public bool? AccountEnabled { get; set; }

    public string UserType { get; set; } = string.Empty;

    public string Department { get; set; } = string.Empty;

    public string JobTitle { get; set; } = string.Empty;

    public string EmployeeId { get; set; } = string.Empty;

    public string ManagerDisplayName { get; set; } = string.Empty;

    public string DetectionReason { get; set; } = string.Empty;
}