namespace CloudX.EntraID.DTOs
{
    public class EntraUserDto
    {
        public string Id { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public string UserPrincipalName { get; set; } = string.Empty;

        public string Mail { get; set; } = string.Empty;

        public bool? AccountEnabled { get; set; }

        public string UserType { get; set; } = string.Empty;

        public string JobTitle { get; set; } = string.Empty;

        public string Department { get; set; } = string.Empty;

        public DateTimeOffset? CreatedDateTime { get; set; }
    }
}