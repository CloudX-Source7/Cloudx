using Azure.Monitor.Query;
using Azure.ResourceManager;
using CloudX.AzureConnection.Repositories;
using CloudX.AzureConnection.Services;
using CloudX.AzureDiscovery.Services;
using CloudX.Data;
using CloudX.Data.Configurations;
using CloudX.EntraID.Graph;
using CloudX.EntraID.Services.AccessLifecycleAudit;
using CloudX.EntraID.Services.AccountDisable;
using CloudX.EntraID.Services.DepartedEmployee;
using CloudX.EntraID.Services.EntraUser;
using CloudX.EntraID.Services.ExcessivePrivilege;
using CloudX.EntraID.Services.InactiveUser;
using CloudX.EntraID.Services.MfaEnforcement;
using CloudX.EntraID.Services.OrphanedAccount;
using CloudX.EntraID.Services.PrivilegedAccount;
using CloudX.Models;
using CloudX.Remediation.Models;
using CloudX.Remediation.Services;
using CloudX.Repositories;
using CloudX.SecurityMonitoring.Rules.Misconfiguration;
using CloudX.SecurityMonitoring.Rules.PublicExposure;
using CloudX.SecurityMonitoring.Services;
using CloudX.SecurityMonitoring.Services.Encryption;
using CloudX.SecurityMonitoring.Services.IdentityAccess;
using CloudX.SecurityMonitoring.Services.PublicExposure;
using CloudX.SecurityMonitoring.Services.StorageDatabase;
using CloudX.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using QuestPDF.Infrastructure;
using System.Text.Json;


QuestPDF.Settings.License = LicenseType.Evaluation;

var builder = WebApplication.CreateBuilder(args);


builder.Services.AddSingleton<RemediationCatalogLoader>();

builder.Services.AddSingleton<IReadOnlyList<RemediationCatalogEntry>>(
    serviceProvider =>
    {
        var loader = serviceProvider.GetRequiredService<
            RemediationCatalogLoader>();

        return loader.Load();
    });
// Remediation Engine — Services
builder.Services.AddScoped<RemediationInputService>();
builder.Services.AddScoped<RemediationCatalogMatcher>();
builder.Services.AddScoped<RemediationParameterResolver>();
builder.Services.AddScoped<RemediationValidator>();
builder.Services.AddScoped<RemediationCliGenerator>();

const string CloudXLocalScheme = "CloudXLocal";
const string AzureCookieScheme = "AzureCookies";

// ============================================================
// Authentication
// ============================================================

builder.Services
    .AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = CloudXLocalScheme;
        options.DefaultSignInScheme = CloudXLocalScheme;
        options.DefaultChallengeScheme = CloudXLocalScheme;
    })
    .AddCookie(CloudXLocalScheme, options =>
    {
        options.LoginPath = "/LogReg/Login";
        options.AccessDeniedPath = "/LogReg/Login";
        options.Cookie.Name = "CloudX.Local";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    })
    .AddMicrosoftIdentityWebApp(
        builder.Configuration.GetSection("AzureAd"),
        OpenIdConnectDefaults.AuthenticationScheme,
        AzureCookieScheme)
    .EnableTokenAcquisitionToCallDownstreamApi(
        new[]
        {
            "https://management.azure.com/user_impersonation",
            "User.Read.All"
        })
    .AddMicrosoftGraph()
    .AddInMemoryTokenCaches();

// ============================================================
// Email configuration
// ============================================================

builder.Services.Configure<EmailSettings>(
    builder.Configuration.GetSection("EmailSettings"));

// ============================================================
// OpenID Connect
// ============================================================

builder.Services.Configure<OpenIdConnectOptions>(
    OpenIdConnectDefaults.AuthenticationScheme,
    options =>
    {
        options.CallbackPath = "/signin-oidc";

        options.CorrelationCookie.SameSite = SameSiteMode.None;
        options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.CorrelationCookie.HttpOnly = true;
        options.CorrelationCookie.IsEssential = true;

        options.NonceCookie.SameSite = SameSiteMode.None;
        options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
        options.NonceCookie.HttpOnly = true;
        options.NonceCookie.IsEssential = true;
    });

// ============================================================
// Azure SDK authentication
// ============================================================

builder.Services.AddMicrosoftIdentityAzureTokenCredential();

builder.Services.AddScoped<ArmClient>(sp =>
{
    var credential =
        sp.GetRequiredService<MicrosoftIdentityTokenCredential>();

    credential.Options.AcquireTokenOptions.AuthenticationOptionsName =
        OpenIdConnectDefaults.AuthenticationScheme;

    return new ArmClient(credential);
});

builder.Services.AddScoped<MetricsQueryClient>(sp =>
{
    var credential =
        sp.GetRequiredService<MicrosoftIdentityTokenCredential>();

    credential.Options.AcquireTokenOptions.AuthenticationOptionsName =
        OpenIdConnectDefaults.AuthenticationScheme;

    return new MetricsQueryClient(credential);
});

// ============================================================
// Cookie policy and MVC
// ============================================================

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.MinimumSameSitePolicy = SameSiteMode.None;
    options.Secure = CookieSecurePolicy.Always;
});

builder.Services.AddControllersWithViews();
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "RequestVerificationToken";
});

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpContextAccessor();
builder.Services.AddMemoryCache();

// ============================================================
// User services and authorization
// ============================================================

builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<ILogRegService, LogRegService>();

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy =
        new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build();
});

// ============================================================
// Database
// ============================================================

builder.Services.AddDbContext<CloudDbContext>(options =>
    options.UseSqlServer(
        builder.Configuration.GetConnectionString("DefaultConnection")));

// ============================================================
// Security monitoring — misconfiguration
// ============================================================

builder.Services.AddScoped<IMisconfigurationService, MisconfigurationService>();
builder.Services.AddScoped<WebAppHttpsOnlyRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.WebAppAuthenticationRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.WebAppManagedIdentityRule>();

builder.Services.AddScoped<WebAppRemoteDebuggingRule>();
builder.Services.AddScoped<WebAppBasicAuthenticationRule>();
builder.Services.AddScoped<WebAppCorsRule>();
builder.Services.AddScoped<WebAppFtpStateRule>();
builder.Services.AddScoped<WebAppLoggingRule>();

builder.Services.AddScoped<SqlPublicNetworkRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.SqlFirewallRule>();

builder.Services.AddScoped<SqlTlsRule>();
builder.Services.AddScoped<StoragePublicAccessRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.StorageSecureTransferRule>();

builder.Services.AddScoped<StorageNetworkRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.KeyVaultPublicNetworkRule>();

builder.Services.AddScoped<KeyVaultSoftDeleteRule>();
builder.Services.AddScoped<KeyVaultPurgeProtectionRule>();

// ============================================================
// Public exposure
// ============================================================

builder.Services.AddScoped<IPublicExposureService, PublicExposureService>();
builder.Services.AddScoped<WebAppPublicAccessRule>();
builder.Services.AddScoped<SqlPublicAccessRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.PublicExposure.StoragePublicBlobRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.PublicExposure.KeyVaultPublicNetworkRule>();

// ============================================================
// Identity access
// ============================================================

builder.Services.AddScoped<IIdentityAccessService, IdentityAccessService>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.WebAppManagedIdentityRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.WebAppAuthenticationRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.KeyVaultAccessPolicyRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.KeyVaultRbacRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.StorageRbacRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.IdentityAccess.SqlAuthenticationRule>();

// ============================================================
// Encryption
// ============================================================

builder.Services.AddScoped<IEncryptionService, EncryptionService>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.StorageEncryptionRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.StorageCustomerManagedKeyRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.SqlEncryptionRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.SqlCustomerManagedKeyRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.KeyVaultKeyProtectionRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Encryption.WebAppTlsRule>();

// ============================================================
// Network firewall
// ============================================================

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.SqlFirewallRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Services.NetworkFirewall.INetworkFirewallService,
    CloudX.SecurityMonitoring.Services.NetworkFirewall.NetworkFirewallService>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.SqlPublicNetworkRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.StorageNetworkRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.KeyVaultFirewallRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.NsgOpenInternetRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.NsgBroadInboundRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.NetworkFirewall.SubnetMissingNsgRule>();

// ============================================================
// Storage and database rules
// ============================================================

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.StoragePublicBlobRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.StorageSecureTransferRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.StorageSharedKeyAccessRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.SqlFirewallRule>();

builder.Services.AddScoped<IStorageDatabaseServices, StorageDatabaseService>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.SqlEncryptionRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.SqlPrivateEndpointRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.StorageDatabase.StorageSharedAccessSignatureExpiryRule>();

builder.Services.AddScoped<
    CloudX.SecurityMonitoring.Rules.Misconfiguration.ActivityLogAlertMissingRule>();

// ============================================================
// Microsoft Entra ID services
// ============================================================

builder.Services.AddScoped<IEntraGraphClient, EntraGraphClient>();
builder.Services.AddScoped<IEntraUserService, EntraUserService>();
builder.Services.AddScoped<IInactiveAccountService, InactiveAccountService>();
builder.Services.AddScoped<IOrphanedAccountService, OrphanedAccountService>();
builder.Services.AddScoped<IDepartedEmployeeService, DepartedEmployeeService>();
builder.Services.AddScoped<IMfaEnforcementService, MfaEnforcementService>();
builder.Services.AddScoped<IPrivilegedAccountService, PrivilegedAccountService>();
builder.Services.AddScoped<IExcessivePrivilegeService, ExcessivePrivilegeService>();
builder.Services.AddScoped<IAccountDisableService, AccountDisableService>();
builder.Services.AddScoped<
    IAccessLifecycleAuditService,
    AccessLifecycleAuditService>();


// ============================================================
// Azure connection and discovery
// ============================================================

builder.Services.AddScoped<IAzureConnectionService, AzureConnectionService>();
builder.Services.AddScoped<IAzureConnectionRepository, AzureConnectionRepository>();
builder.Services.AddScoped<IAzureDiscoveryService, AzureDiscoveryService>();


// ============================================================
// Build application
// ============================================================

builder.Services.AddHttpClient();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Start}/{action=Index}/{id?}");

app.MapControllers();

app.Run();