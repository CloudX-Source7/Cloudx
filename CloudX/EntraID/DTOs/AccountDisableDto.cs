namespace CloudX.EntraID.DTOs;

public class AccountDisableDto
{
    public string UserId { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public string UserType { get; set; } = string.Empty;

    public bool? AccountEnabled { get; set; }

    public string Result { get; set; } = string.Empty;

    public string Message { get; set; } = string.Empty;
}