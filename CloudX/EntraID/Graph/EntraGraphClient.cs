using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Identity.Web;
using Microsoft.Kiota.Abstractions.Authentication;

namespace CloudX.EntraID.Graph;

public class EntraGraphClient : IEntraGraphClient
{
    private const string AzureCookieScheme = "AzureCookies";
    private const string OpenIdConnectScheme = "OpenIdConnect";

    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly ITokenAcquisition _tokenAcquisition;

    public EntraGraphClient(
        IHttpContextAccessor httpContextAccessor,
        ITokenAcquisition tokenAcquisition)
    {
        _httpContextAccessor = httpContextAccessor;
        _tokenAcquisition = tokenAcquisition;
    }

    // =========================================================
    // USER INVENTORY
    // =========================================================

    public async Task<List<User>> GetUsersAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var users = new List<User>();

        var response = await graphClient.Users.GetAsync(options =>
        {
            options.QueryParameters.Select = new[]
            {
                "id",
                "displayName",
                "userPrincipalName",
                "mail",
                "accountEnabled",
                "userType",
                "jobTitle",
                "department",
                "createdDateTime"
            };

            options.QueryParameters.Top = 999;
        });

        while (response != null)
        {
            if (response.Value != null)
            {
                users.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response = await graphClient.Users
                .WithUrl(response.OdataNextLink)
                .GetAsync();
        }

        return users;
    }

    // =========================================================
    // INACTIVE ACCOUNT DETECTION
    // =========================================================

    public async Task<List<User>> GetUsersWithSignInActivityAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var users = new List<User>();

        var response = await graphClient.Users.GetAsync(options =>
        {
            options.QueryParameters.Select = new[]
            {
                "id",
                "displayName",
                "userPrincipalName",
                "mail",
                "accountEnabled",
                "userType",
                "jobTitle",
                "department",
                "createdDateTime",
                "signInActivity"
            };

            options.QueryParameters.Top = 500;
        });

        while (response != null)
        {
            if (response.Value != null)
            {
                users.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response = await graphClient.Users
                .WithUrl(response.OdataNextLink)
                .GetAsync();
        }

        return users;
    }

    // =========================================================
    // ORPHANED ACCOUNT DETECTION
    // =========================================================

    public async Task<List<User>> GetUsersForOrphanDetectionAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var users = new List<User>();

        var response = await graphClient.Users.GetAsync(options =>
        {
            options.QueryParameters.Select = new[]
            {
                "id",
                "displayName",
                "userPrincipalName",
                "accountEnabled",
                "userType",
                "department",
                "jobTitle",
                "employeeId",
                "createdDateTime"
            };

            options.QueryParameters.Expand = new[]
            {
                "manager($select=id,displayName,userPrincipalName)"
            };

            options.QueryParameters.Top = 999;
        });

        while (response != null)
        {
            if (response.Value != null)
            {
                users.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response = await graphClient.Users
                .WithUrl(response.OdataNextLink)
                .GetAsync();
        }

        return users;
    }

    // =========================================================
    // DEPARTED EMPLOYEE DETECTION
    // =========================================================

    public async Task<List<User>>
        GetUsersForDepartedEmployeeDetectionAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var users = new List<User>();

        var response = await graphClient.Users.GetAsync(options =>
        {
            options.QueryParameters.Select = new[]
            {
                "id",
                "displayName",
                "userPrincipalName",
                "userType",
                "accountEnabled",
                "employeeId",
                "department",
                "jobTitle",
                "employeeLeaveDateTime"
            };

            options.QueryParameters.Top = 999;
        });

        while (response != null)
        {
            if (response.Value != null)
            {
                users.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response = await graphClient.Users
                .WithUrl(response.OdataNextLink)
                .GetAsync();
        }

        return users;
    }

    // =========================================================
    // MFA CHECK
    // =========================================================

    public async Task<List<User>> GetUsersForMfaCheckAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var users = new List<User>();

        var response = await graphClient.Users.GetAsync(options =>
        {
            options.QueryParameters.Select = new[]
            {
                "id",
                "displayName",
                "userPrincipalName",
                "userType"
            };

            options.QueryParameters.Top = 999;
        });

        while (response != null)
        {
            if (response.Value != null)
            {
                users.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response =
                await graphClient
                    .Users
                    .WithUrl(response.OdataNextLink)
                    .GetAsync();
        }

        return users;
    }

    public async Task<List<AuthenticationMethod>>
        GetUserAuthenticationMethodsAsync(string userId)
    {
        var graphClient = await CreateGraphClientAsync();

        var methods = new List<AuthenticationMethod>();

        var response =
            await graphClient
                .Users[userId]
                .Authentication
                .Methods
                .GetAsync();

        if (response?.Value != null)
        {
            methods.AddRange(response.Value);
        }

        return methods;
    }

    // =========================================================
    // PRIVILEGED ACCOUNT REVIEW
    // =========================================================

    public async Task<List<UnifiedRoleAssignment>>
        GetDirectoryRoleAssignmentsAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var assignments =
            new List<UnifiedRoleAssignment>();

        var response =
            await graphClient
                .RoleManagement
                .Directory
                .RoleAssignments
                .GetAsync(options =>
                {
                    options.QueryParameters.Top = 999;
                });

        while (response != null)
        {
            if (response.Value != null)
            {
                assignments.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response =
                await graphClient
                    .RoleManagement
                    .Directory
                    .RoleAssignments
                    .WithUrl(response.OdataNextLink)
                    .GetAsync();
        }

        return assignments;
    }

    public async Task<List<UnifiedRoleDefinition>>
    GetDirectoryRoleDefinitionsAsync()
    {
        var graphClient = await CreateGraphClientAsync();

        var definitions =
            new List<UnifiedRoleDefinition>();

        var response =
            await graphClient
                .RoleManagement
                .Directory
                .RoleDefinitions
                .GetAsync();

        while (response != null)
        {
            if (response.Value != null)
            {
                definitions.AddRange(response.Value);
            }

            if (string.IsNullOrEmpty(response.OdataNextLink))
            {
                break;
            }

            response =
                await graphClient
                    .RoleManagement
                    .Directory
                    .RoleDefinitions
                    .WithUrl(response.OdataNextLink)
                    .GetAsync();
        }

        return definitions;
    }

    public async Task<User?> GetUserByIdAsync(string userId)
    {
        var graphClient = await CreateGraphClientAsync();

        return await graphClient
            .Users[userId]
            .GetAsync(options =>
            {
                options.QueryParameters.Select =
                    new[]
                    {
                        "id",
                        "displayName",
                        "userPrincipalName",
                        "userType",
                        "accountEnabled"
                    };
            });
    }

    // =========================================================
    // GRAPH CLIENT CREATION
    // =========================================================

    private async Task<GraphServiceClient>
        CreateGraphClientAsync()
    {
        var httpContext =
            _httpContextAccessor.HttpContext;

        if (httpContext == null)
        {
            throw new InvalidOperationException(
                "HTTP context is not available.");
        }

        var azureAuthentication =
            await httpContext.AuthenticateAsync(
                AzureCookieScheme);

        if (!azureAuthentication.Succeeded ||
            azureAuthentication.Principal == null)
        {
            throw new InvalidOperationException(
                "Azure/Entra authentication was not found.");
        }

        ClaimsPrincipal azureUser =
            azureAuthentication.Principal;

        var accessToken =
            await _tokenAcquisition.GetAccessTokenForUserAsync(
                scopes: new[]
                {
                    "User.Read.All",
                    "AuditLog.Read.All",
                    "Directory.Read.All",
                    "User-LifeCycleInfo.Read.All",
                    "UserAuthenticationMethod.Read.All",
                    "RoleManagement.Read.Directory",
                    "User.EnableDisableAccount.All",
                    "User.EnableDisableAccount.All"
                },
                authenticationScheme: OpenIdConnectScheme,
                tenantId: null,
                userFlow: null,
                user: azureUser,
                tokenAcquisitionOptions: null);

        var authenticationProvider =
            new BaseBearerTokenAuthenticationProvider(
                new AccessTokenProvider(accessToken));

        return new GraphServiceClient(
            authenticationProvider);
    }

    // =========================================================
    // ACCESS TOKEN PROVIDER
    // =========================================================

    private sealed class AccessTokenProvider
        : IAccessTokenProvider
    {
        private readonly string _accessToken;

        public AccessTokenProvider(
            string accessToken)
        {
            _accessToken = accessToken;
        }

        public Task<string>
            GetAuthorizationTokenAsync(
                Uri uri,
                Dictionary<string, object>?
                    additionalAuthenticationContext = null,
                CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_accessToken);
        }

        public AllowedHostsValidator
            AllowedHostsValidator
        { get; } =
            new AllowedHostsValidator(
                new[]
                {
                    "graph.microsoft.com"
                });
    }
    public async Task DisableUserAsync(string userId)
    {
        if (string.IsNullOrWhiteSpace(userId))
        {
            throw new ArgumentException(
                "User ID is required.",
                nameof(userId));
        }

        var graphClient =
            await CreateGraphClientAsync();

        var user = new User
        {
            AccountEnabled = false
        };

        await graphClient
            .Users[userId]
            .PatchAsync(user);
    }
}