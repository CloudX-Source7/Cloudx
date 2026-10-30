using CloudX.EntraID.Services.DepartedEmployee;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.EntraID.Controllers;

[Authorize]
public class DepartedEmployeeController : Controller
{
    private readonly IDepartedEmployeeService
        _departedEmployeeService;

    public DepartedEmployeeController(
        IDepartedEmployeeService departedEmployeeService)
    {
        _departedEmployeeService =
            departedEmployeeService;
    }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var departedEmployees =
            await _departedEmployeeService
                .GetDepartedEmployeesAsync();

        return View(
            "~/Views/EntraUser/DepartedEmployees.cshtml",
            departedEmployees);
    }
}