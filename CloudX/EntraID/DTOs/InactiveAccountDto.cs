namespace CloudX.EntraID.DTOs;

public class InactiveAccountDto
{
    public string Id { get; set; } = string.Empty;

    public string DisplayName { get; set; } = string.Empty;

    public string UserPrincipalName { get; set; } = string.Empty;

    public DateTimeOffset? LastSignInDateTime { get; set; }

    public int? InactiveDays { get; set; }

    public bool? AccountEnabled { get; set; }

    public string UserType { get; set; } = string.Empty;
}