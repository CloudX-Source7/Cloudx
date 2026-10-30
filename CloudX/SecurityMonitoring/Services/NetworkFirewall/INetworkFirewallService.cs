using CloudX.SecurityMonitoring.Dto;
using CloudX.SecurityMonitoring.UniversalRuleSupport;

namespace CloudX.SecurityMonitoring.Services.NetworkFirewall;

public interface INetworkFirewallService
{
    Task<List<SecurityFindingDto>>
        CheckSqlFirewallAsync(
            string entraTenantId);

    Task<List<SecurityFindingDto>>
        CheckSqlPublicNetworkAsync(
            string entraTenantId);

    Task<List<SecurityFindingDto>>
        CheckStorageNetworkAsync(
            string entraTenantId);

    Task<List<SecurityFindingDto>>
        CheckKeyVaultFirewallAsync(
            string entraTenantId);
    Task<List<SecurityFindingDto>>
    CheckNsgOpenInternetAsync(
        string entraTenantId);
    Task<List<SecurityFindingDto>>
    CheckNsgBroadInboundAsync(
        string entraTenantId);
    Task<List<SecurityFindingDto>>
    CheckSubnetMissingNsgAsync(
        string entraTenantId);
    Task<List<UniversalResultDto>> ScanAsync(
    string entraTenantId);
}