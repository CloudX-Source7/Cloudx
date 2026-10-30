using System.ComponentModel.DataAnnotations;

namespace CloudX.DTOs;

public class LoginDto
{
    [Required]
    [EmailAddress]
    [MaxLength(200)]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}