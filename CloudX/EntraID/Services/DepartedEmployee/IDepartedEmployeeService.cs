using CloudX.EntraID.DTOs;

namespace CloudX.EntraID.Services.DepartedEmployee;

public interface IDepartedEmployeeService
{
    Task<List<DepartedEmployeeDto>>
        GetDepartedEmployeesAsync();
}