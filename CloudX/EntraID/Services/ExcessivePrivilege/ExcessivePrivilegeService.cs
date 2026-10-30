using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;
using Microsoft.Graph.Models;

namespace CloudX.EntraID.Services.ExcessivePrivilege;

public class ExcessivePrivilegeService
    : IExcessivePrivilegeService
{
    private readonly IEntraGraphClient _graphClient;

    public ExcessivePrivilegeService(
        IEntraGraphClient graphClient)
    {
        _graphClient = graphClient;
    }

    public async Task<List<ExcessivePrivilegeDto>>
        GetExcessivePrivilegeFindingsAsync()
    {
        var assignments =
            await _graphClient
                .GetDirectoryRoleAssignmentsAsync();

        var definitions =
            await _graphClient
                .GetDirectoryRoleDefinitionsAsync();

        var roleDefinitions =
            definitions
                .Where(role =>
                    !string.IsNullOrWhiteSpace(role.Id))
                .ToDictionary(
                    role => role.Id!,
                    role => role.DisplayName ?? "Unknown Role",
                    StringComparer.OrdinalIgnoreCase);

        var userAssignments =
            assignments
                .Where(assignment =>
                    !string.IsNullOrWhiteSpace(
                        assignment.PrincipalId) &&
                    !string.IsNullOrWhiteSpace(
                        assignment.RoleDefinitionId))
                .GroupBy(
                    assignment => assignment.PrincipalId!,
                    StringComparer.OrdinalIgnoreCase);

        var findings =
            new List<ExcessivePrivilegeDto>();

        foreach (var group in userAssignments)
        {
            var userId = group.Key;

            User? user;

            try
            {
                user =
                    await _graphClient
                        .GetUserByIdAsync(userId);
            }
            catch
            {
                // The principal may not be a user.
                continue;
            }

            if (user == null)
            {
                continue;
            }

            var roleNames =
                group
                    .Select(assignment =>
                        roleDefinitions.TryGetValue(
                            assignment.RoleDefinitionId!,
                            out var roleName)
                            ? roleName
                            : "Unknown Role")
                    .Distinct(
                        StringComparer.OrdinalIgnoreCase)
                    .OrderBy(role => role)
                    .ToList();

            if (roleNames.Count == 0)
            {
                continue;
            }

            var rules =
                DetectExcessivePrivilegeRules(
                    user,
                    roleNames);

            foreach (var rule in rules)
            {
                findings.Add(
                    new ExcessivePrivilegeDto
                    {
                        UserId =
                            user.Id ?? string.Empty,

                        DisplayName =
                            user.DisplayName ?? string.Empty,

                        UserPrincipalName =
                            user.UserPrincipalName ?? string.Empty,

                        UserType =
                            user.UserType ?? string.Empty,

                        AccountEnabled =
                            user.AccountEnabled,

                        PrivilegedRoleCount =
                            roleNames.Count,

                        PrivilegedRoles =
                            string.Join(
                                ", ",
                                roleNames),

                        DetectionRule =
                            rule.Rule,

                        DetectionReason =
                            rule.Reason
                    });
            }
        }

        return findings
            .OrderBy(f => f.DisplayName)
            .ThenBy(f => f.DetectionRule)
            .ToList();
    }

    private static List<PrivilegeRuleResult>
        DetectExcessivePrivilegeRules(
            User user,
            List<string> roleNames)
    {
        var results =
            new List<PrivilegeRuleResult>();

        // -----------------------------------------------------
        // RULE 1
        // Multiple privileged roles
        // -----------------------------------------------------

        if (roleNames.Count >= 2)
        {
            results.Add(
                new PrivilegeRuleResult
                {
                    Rule =
                        "Multiple Privileged Roles",

                    Reason =
                        $"User has {roleNames.Count} " +
                        "Microsoft Entra directory roles."
                });
        }

        // -----------------------------------------------------
        // RULE 2
        // Global Administrator + another role
        // -----------------------------------------------------

        var hasGlobalAdministrator =
            HasRole(
                roleNames,
                "Global Administrator");

        if (hasGlobalAdministrator &&
            roleNames.Count >= 2)
        {
            results.Add(
                new PrivilegeRuleResult
                {
                    Rule =
                        "Global Administrator Role Combination",

                    Reason =
                        "User has Global Administrator " +
                        "together with one or more additional " +
                        "directory roles."
                });
        }

        // -----------------------------------------------------
        // RULE 3
        // Privileged Role Administrator + another role
        // -----------------------------------------------------

        var hasPrivilegedRoleAdministrator =
            HasRole(
                roleNames,
                "Privileged Role Administrator");

        if (hasPrivilegedRoleAdministrator &&
            roleNames.Count >= 2)
        {
            results.Add(
                new PrivilegeRuleResult
                {
                    Rule =
                        "Privileged Role Administrator Combination",

                    Reason =
                        "User has Privileged Role Administrator " +
                        "together with one or more additional " +
                        "directory roles."
                });
        }

        // -----------------------------------------------------
        // RULE 4
        // Guest with privileged access
        // -----------------------------------------------------

        var isGuest =
            string.Equals(
                user.UserType,
                "Guest",
                StringComparison.OrdinalIgnoreCase);

        if (isGuest &&
            roleNames.Count > 0)
        {
            results.Add(
                new PrivilegeRuleResult
                {
                    Rule =
                        "Guest Privileged Access",

                    Reason =
                        "Guest account has one or more " +
                        "Microsoft Entra directory roles."
                });
        }

        // -----------------------------------------------------
        // RULE 5
        // Guest with high-impact privileged role
        // -----------------------------------------------------

        if (isGuest &&
            roleNames.Any(IsHighImpactRole))
        {
            results.Add(
                new PrivilegeRuleResult
                {
                    Rule =
                        "Guest High-Impact Privilege",

                    Reason =
                        "Guest account has a high-impact " +
                        "Microsoft Entra directory role."
                });
        }

        return results;
    }

    private static bool HasRole(
        IEnumerable<string> roles,
        string roleName)
    {
        return roles.Any(
            role =>
                string.Equals(
                    role,
                    roleName,
                    StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsHighImpactRole(
        string roleName)
    {
        return
            HasRole(
                new[] { roleName },
                "Global Administrator")
            ||
            HasRole(
                new[] { roleName },
                "Privileged Role Administrator")
            ||
            HasRole(
                new[] { roleName },
                "Security Administrator")
            ||
            HasRole(
                new[] { roleName },
                "Application Administrator")
            ||
            HasRole(
                new[] { roleName },
                "Cloud Application Administrator");
    }

    private sealed class PrivilegeRuleResult
    {
        public string Rule { get; set; } = string.Empty;

        public string Reason { get; set; } = string.Empty;
    }
}