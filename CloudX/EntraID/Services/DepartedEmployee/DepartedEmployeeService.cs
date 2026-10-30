using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;

namespace CloudX.EntraID.Services.DepartedEmployee;

public class DepartedEmployeeService : IDepartedEmployeeService
{
    private readonly IEntraGraphClient _graphClient;

    public DepartedEmployeeService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<DepartedEmployeeDto>>
        GetDepartedEmployeesAsync()
    {
        var users =
            await _graphClient
                .GetUsersForDepartedEmployeeDetectionAsync();

        var now = DateTimeOffset.UtcNow;

        var departedEmployees = users
            .Where(user =>
                user.EmployeeLeaveDateTime.HasValue &&
                user.EmployeeLeaveDateTime.Value <= now &&
                user.AccountEnabled == true &&
                string.Equals(
                    user.UserType,
                    "Member",
                    StringComparison.OrdinalIgnoreCase))
            .Select(user =>
            {
                var leaveDate =
                    user.EmployeeLeaveDateTime!.Value;

                var daysSinceDeparture =
                    Math.Max(
                        0,
                        (int)(now - leaveDate).TotalDays);

                return new DepartedEmployeeDto
                {
                    Id =
                        user.Id ?? string.Empty,

                    DisplayName =
                        user.DisplayName ?? string.Empty,

                    UserPrincipalName =
                        user.UserPrincipalName ?? string.Empty,

                    UserType =
                        user.UserType ?? string.Empty,

                    AccountEnabled =
                        user.AccountEnabled,

                    EmployeeId =
                        user.EmployeeId ?? string.Empty,

                    Department =
                        user.Department ?? string.Empty,

                    JobTitle =
                        user.JobTitle ?? string.Empty,

                    EmployeeLeaveDateTime =
                        leaveDate,

                    DaysSinceDeparture =
                        daysSinceDeparture,

                    DetectionReason =
                        "Employee leave date has passed but the account is still enabled."
                };
            })
            .ToList();

        return departedEmployees;
    }
}