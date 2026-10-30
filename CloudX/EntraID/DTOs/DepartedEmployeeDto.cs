namespace CloudX.EntraID.DTOs;

public class DepartedEmployeeDto
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public string UserType { get; set; } = string.Empty;

    public bool? AccountEnabled { get; set; }

    public string EmployeeId { get; set; } = string.Empty;

    public string Department { get; set; } = string.Empty;

    public string JobTitle { get; set; } = string.Empty;

    public DateTimeOffset? EmployeeLeaveDateTime { get; set; }

    public int DaysSinceDeparture { get; set; }

    public string DetectionReason { get; set; } = string.Empty;
}