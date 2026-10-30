
using CloudX.Remediation.Dto;
using CloudX.Remediation.Services;
using Microsoft.AspNetCore.Mvc;

namespace CloudX.Controllers;

public sealed class RemediationController : Controller
{
    private readonly RemediationInputService _inputService;
    private readonly RemediationCatalogMatcher _catalogMatcher;
    private readonly RemediationParameterResolver _parameterResolver;
    private readonly RemediationValidator _validator;
    private readonly RemediationCliGenerator _cliGenerator;

    public RemediationController(
        RemediationInputService inputService,
        RemediationCatalogMatcher catalogMatcher,
        RemediationParameterResolver parameterResolver,
        RemediationValidator validator,
        RemediationCliGenerator cliGenerator)
    {
        _inputService = inputService;
        _catalogMatcher = catalogMatcher;
        _parameterResolver = parameterResolver;
        _validator = validator;
        _cliGenerator = cliGenerator;
    }

    [HttpPost]
    [IgnoreAntiforgeryToken]
    public IActionResult GenerateCli([FromBody] RemediationRequest request)
    {
        try
        {
            // 1. Validate the incoming request.
            var inputError = _inputService.Validate(request);

            if (inputError is not null)
            {
                return BadRequest(new RemediationResult
                {
                    Success = false,
                    Message = inputError
                });
            }

            // 2. Match the selected finding to one catalog entry.
            var entry = _catalogMatcher.Match(request.Finding);

            if (entry is null)
            {
                return NotFound(new RemediationResult
                {
                    Success = false,
                    Message = "No remediation is available for this finding."
                });
            }

            // 3. Resolve parameters using the selected finding.
            var parameters = _parameterResolver.Resolve(
                entry,
                request.Finding,
                request.Parameters);

            // 4. Validate the catalog entry and resolved parameters.
            var validationErrors = _validator.Validate(
                entry,
                parameters);

            if (validationErrors.Count > 0)
            {
                var missingParameters = validationErrors
                    .Where(error => error.StartsWith(
                        "Missing required parameter:",
                        StringComparison.OrdinalIgnoreCase))
                    .Select(error => error[
                        "Missing required parameter:".Length..].Trim())
                    .ToList();

                var otherErrors = validationErrors
                    .Except(
                        validationErrors.Where(error =>
                            error.StartsWith(
                                "Missing required parameter:",
                                StringComparison.OrdinalIgnoreCase)))
                    .ToList();

                if (otherErrors.Count > 0)
                {
                    return BadRequest(new RemediationResult
                    {
                        Success = false,
                        Name = entry.Name,
                        Message = string.Join(" ", otherErrors)
                    });
                }

                return Ok(new RemediationResult
                {
                    Success = false,
                    Name = entry.Name,
                    Description = entry.Description,
                    ImpactWarning = entry.ImpactWarning,
                    RequiresApproval = entry.RequiresApproval,
                    Message = "Additional parameters are required.",
                    CommandTemplate = entry.CommandTemplate,
                    MissingParameters = missingParameters
                });
            }

            // 5. Generate the command. Do not execute it.
            var command = _cliGenerator.Generate(
                entry,
                parameters);

            return Ok(new RemediationResult
            {
                Success = true,
                Name = entry.Name,
                Description = entry.Description,
                ImpactWarning = entry.ImpactWarning,
                RequiresApproval = entry.RequiresApproval,
                Message = "CLI command generated successfully.",
                CommandTemplate = entry.CommandTemplate,
                Command = command
            });
        }
        catch (InvalidOperationException ex)
        {
            return BadRequest(new RemediationResult
            {
                Success = false,
                Message = ex.Message
            });
        }
        catch (ArgumentException ex)
        {
            return BadRequest(new RemediationResult
            {
                Success = false,
                Message = ex.Message
            });
        }
        catch (Exception)
        {
            return StatusCode(500, new RemediationResult
            {
                Success = false,
                Message = "An unexpected error occurred while generating the CLI command."
            });
        }
    }
}
