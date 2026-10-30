using System.ComponentModel.DataAnnotations;

namespace CloudX.Models;

public class User
{
    [Key]
    public int Id { get; set; }

    [Required]
    [MaxLength(200)]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string PasswordHash { get; set; } = string.Empty;

    public bool EmailVerified { get; set; }

    [Required]
    [MaxLength(50)]
    public string Role { get; set; } = "User";

    public DateTime CreatedAt { get; set; }

    public bool IsActive { get; set; }
}