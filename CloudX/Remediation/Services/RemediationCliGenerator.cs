
using System.Text.RegularExpressions;
using CloudX.Remediation.Models;

namespace CloudX.Remediation.Services;

public sealed class RemediationCliGenerator
{
    private static readonly Regex PlaceholderRegex =
        new(@"\{([A-Za-z][A-Za-z0-9_]*)\}",
            RegexOptions.Compiled);

    public string Generate(
        RemediationCatalogEntry entry,
        Dictionary<string, string> parameters)
    {
        if (string.IsNullOrWhiteSpace(entry.CommandTemplate))
        {
            throw new InvalidOperationException(
                "No CLI command template is available.");
        }

        var command = entry.CommandTemplate;

        foreach (var match in PlaceholderRegex.Matches(command)
                     .Cast<Match>()
                     .ToList())
        {
            var parameterName = match.Groups[1].Value;

            if (!parameters.TryGetValue(
                    parameterName,
                    out var parameterValue) ||
                string.IsNullOrWhiteSpace(parameterValue))
            {
                throw new InvalidOperationException(
                    $"Missing parameter: {parameterName}");
            }

            command = command.Replace(
                match.Value,
                EscapePowerShellArgument(parameterValue),
                StringComparison.Ordinal);
        }

        if (PlaceholderRegex.IsMatch(command) ||
            command.Contains('{') ||
            command.Contains('}'))
        {
            throw new InvalidOperationException(
                "The generated command contains unresolved placeholders.");
        }

        return command;
    }

    private static string EscapePowerShellArgument(string value)
    {
        if (value.Any(char.IsControl))
        {
            throw new ArgumentException(
                "Parameter values cannot contain control characters.");
        }

        // PowerShell single-quoted string escaping.
        return "'" + value.Replace("'", "''") + "'";
    }
}
