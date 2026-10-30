namespace CloudX.Models;

public class EmailSettings
{
    public string SenderEmail { get; set; } = string.Empty;

    public string AppPassword { get; set; } = string.Empty;

    public string SmtpHost { get; set; } = string.Empty;

    public int SmtpPort { get; set; }
}