using CloudX.EntraID.DTOs;
using CloudX.EntraID.Graph;
using CloudX.EntraID.Services.AccessLifecycleAudit;
using CloudX.EntraID.Services.AccessLifecycleAudit;
using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace CloudX.EntraID.Services.AccountDisable;

public class AccountDisableService
    : IAccountDisableService
{
    private readonly IEntraGraphClient _graphClient;

    private readonly IAccessLifecycleAuditService
        _auditService;

    private readonly IHttpContextAccessor
        _httpContextAccessor;

    public AccountDisableService(
        IEntraGraphClient graphClient,
        IAccessLifecycleAuditService auditService,
        IHttpContextAccessor httpContextAccessor)
    {
        _graphClient = graphClient;

        _auditService = auditService;

        _httpContextAccessor = httpContextAccessor;
    }

    public async Task<AccountDisableDto>
    DisableAccountAsync(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            throw new ArgumentException(
                "User ID is required.",
                nameof(userId));
        }

        var httpContext =
            _httpContextAccessor.HttpContext;

        var localUserIdValue =
            httpContext?.User.FindFirstValue(
                ClaimTypes.NameIdentifier);

        int? actorUserId = null;

        if (int.TryParse(
            localUserIdValue,
            out var parsedUserId))
        {
            actorUserId = parsedUserId;
        }

        var actorName =
            httpContext?.User.Identity?.Name
            ?? "CloudX User";

        var azureAuthentication =
            await httpContext!
                .AuthenticateAsync("AzureCookies");

        var azureUser =
            azureAuthentication.Principal;

        var entraTenantId =
            azureUser?.FindFirstValue("tid")
            ?? string.Empty;

        Microsoft.Graph.Models.User? user = null;

        try
        {
            user =
                await _graphClient
                    .GetUserByIdAsync(userId);

            if (user == null)
            {
                await _auditService.RecordAsync(
                    action: "Disable Account",
                    result: "Failed",
                    actorUserId: actorUserId,
                    actorName: actorName,
                    entraTenantId: entraTenantId,
                    targetUserId: userId,
                    targetDisplayName: string.Empty,
                    targetUserPrincipalName: string.Empty,
                    details: "Target Entra user was not found.");

                throw new InvalidOperationException(
                    "The requested Entra user was not found.");
            }

            var targetDisplayName =
                user.DisplayName ?? string.Empty;

            var targetUpn =
                user.UserPrincipalName ?? string.Empty;

            if (user.AccountEnabled == false)
            {
                await _auditService.RecordAsync(
                    action: "Disable Account",
                    result: "Already Disabled",
                    actorUserId: actorUserId,
                    actorName: actorName,
                    entraTenantId: entraTenantId,
                    targetUserId: user.Id ?? userId,
                    targetDisplayName: targetDisplayName,
                    targetUserPrincipalName: targetUpn,
                    details: "The Entra account was already disabled.");

                return new AccountDisableDto
                {
                    UserId = user.Id ?? userId,
                    DisplayName = targetDisplayName,
                    UserPrincipalName = targetUpn,
                    UserType = user.UserType ?? string.Empty,
                    AccountEnabled = false,
                    Result = "AlreadyDisabled",
                    Message = "The account is already disabled."
                };
            }

            await _graphClient
                .DisableUserAsync(userId);

            await _auditService.RecordAsync(
                action: "Disable Account",
                result: "Success",
                actorUserId: actorUserId,
                actorName: actorName,
                entraTenantId: entraTenantId,
                targetUserId: user.Id ?? userId,
                targetDisplayName: targetDisplayName,
                targetUserPrincipalName: targetUpn,
                details: "The Entra account was successfully disabled.");

            return new AccountDisableDto
            {
                UserId = user.Id ?? userId,
                DisplayName = targetDisplayName,
                UserPrincipalName = targetUpn,
                UserType = user.UserType ?? string.Empty,
                AccountEnabled = false,
                Result = "Disabled",
                Message = "The Entra account was successfully disabled."
            };
        }
        catch (Exception ex)
        {
            if (user != null)
            {
                await _auditService.RecordAsync(
                    action: "Disable Account",
                    result: "Failed",
                    actorUserId: actorUserId,
                    actorName: actorName,
                    entraTenantId: entraTenantId,
                    targetUserId: user.Id ?? userId,
                    targetDisplayName:
                        user.DisplayName ?? string.Empty,
                    targetUserPrincipalName:
                        user.UserPrincipalName ?? string.Empty,
                    details: ex.Message);
            }

            throw;
        }
    }
}