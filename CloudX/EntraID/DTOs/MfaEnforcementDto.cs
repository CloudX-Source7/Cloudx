namespace CloudX.EntraID.DTOs;

public class MfaEnforcementDto
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public string UserType { get; set; } = string.Empty;

    public bool IsAdmin { get; set; }

    public bool IsMfaRegistered { get; set; }

    public bool IsMfaCapable { get; set; }

    public string DefaultMfaMethod { get; set; } = string.Empty;

    public string DetectionReason { get; set; } = string.Empty;
}