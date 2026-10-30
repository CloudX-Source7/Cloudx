
using CloudX.Remediation.Models;

namespace CloudX.Remediation.Services;

public sealed class RemediationValidator
{
    public List<string> Validate(
        RemediationCatalogEntry entry,
        Dictionary<string, string> parameters)
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(entry.Id))
            errors.Add("Remediation ID is missing.");

        if (string.IsNullOrWhiteSpace(entry.Name))
            errors.Add("Remediation name is missing.");

        if (string.IsNullOrWhiteSpace(entry.CommandTemplate))
            errors.Add("No generic CLI command is available for this remediation.");

        if (entry.RequiredParameters is null)
            errors.Add("Required parameter definitions are missing.");

        if (parameters is null)
            errors.Add("Remediation parameters are missing.");

        if (errors.Count > 0)
            return errors;

        foreach (var parameter in entry.RequiredParameters)
        {
            if (!parameters.TryGetValue(parameter, out var value) ||
                string.IsNullOrWhiteSpace(value))
            {
                errors.Add($"Missing required parameter: {parameter}");
            }
        }

        // Verify every template placeholder is declared.
        var placeholders = System.Text.RegularExpressions.Regex
            .Matches(entry.CommandTemplate, @"\{([^{}]+)\}")
            .Select(match => match.Groups[1].Value)
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var placeholder in placeholders)
        {
            if (!entry.RequiredParameters.Contains(
                    placeholder,
                    StringComparer.OrdinalIgnoreCase))
            {
                errors.Add(
                    $"Template placeholder '{placeholder}' is not declared in RequiredParameters.");
            }
        }

        return errors;
    }
}
