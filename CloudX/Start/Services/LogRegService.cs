using CloudX.DTOs;
using CloudX.Models;
using CloudX.Repositories;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Net;
using System.Net.Mail;

namespace CloudX.Services;

public sealed class LogRegService : ILogRegService
{
    private readonly IMemoryCache _cache;
    private readonly EmailSettings _emailSettings;
    private readonly IUserRepository _userRepository;

    public LogRegService(
        IMemoryCache cache,
        IOptions<EmailSettings> emailSettings,
        IUserRepository userRepository)
    {
        _cache = cache;
        _emailSettings = emailSettings.Value;
        _userRepository = userRepository;
    }

    public async Task<bool> RegisterAsync(
        RegisterDto model,
        CancellationToken cancellationToken = default)
    {
        if (model == null)
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(model.Email))
        {
            return false;
        }

        var email =
            NormalizeEmail(model.Email);

        var emailExists =
            await _userRepository.EmailExistsAsync(
                email,
                cancellationToken);

        if (emailExists)
        {
            return false;
        }

        var otp =
            Random.Shared
                .Next(100000, 1000000)
                .ToString();

        var otpKey =
            GetOtpKey(email);

        var registrationKey =
            GetRegistrationKey(email);

        _cache.Set(
            otpKey,
            otp,
            TimeSpan.FromMinutes(5));

        _cache.Set(
            registrationKey,
            model,
            TimeSpan.FromMinutes(5));

        try
        {
            using var message =
                new MailMessage();

            message.From =
                new MailAddress(
                    _emailSettings.SenderEmail);

            message.To.Add(email);

            message.Subject =
                "CloudX Email Verification";

            message.Body =
                $"""
                Hello,

                Your CloudX verification OTP is:

                {otp}

                This OTP is valid for 5 minutes.

                If you did not request this verification,
                please ignore this email.

                CloudX
                """;

            message.IsBodyHtml = false;

            using var smtp =
                new SmtpClient(
                    _emailSettings.SmtpHost,
                    _emailSettings.SmtpPort);

            smtp.EnableSsl = true;

            smtp.Credentials =
                new NetworkCredential(
                    _emailSettings.SenderEmail,
                    _emailSettings.AppPassword);

            await smtp.SendMailAsync(
                message,
                cancellationToken);

            return true;
        }
        catch
        {
            _cache.Remove(otpKey);
            _cache.Remove(registrationKey);

            return false;
        }
    }

    public async Task<bool> VerifyOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(otp))
        {
            return false;
        }

        var normalizedEmail =
            NormalizeEmail(email);

        var otpKey =
            GetOtpKey(normalizedEmail);

        var registrationKey =
            GetRegistrationKey(normalizedEmail);

        if (!_cache.TryGetValue(
                otpKey,
                out string? storedOtp))
        {
            return false;
        }

        if (!string.Equals(
                storedOtp,
                otp.Trim(),
                StringComparison.Ordinal))
        {
            return false;
        }

        if (!_cache.TryGetValue(
                registrationKey,
                out RegisterDto? model))
        {
            return false;
        }

        var passwordHash =
            BCrypt.Net.BCrypt.HashPassword(
                model.Password);

        var user = new User
        {
            Email = normalizedEmail,
            PasswordHash = passwordHash,
            EmailVerified = true,
            Role = "User",
            CreatedAt = DateTime.UtcNow,
            IsActive = true
        };

        await _userRepository.CreateAsync(
            user,
            cancellationToken);

        _cache.Remove(otpKey);
        _cache.Remove(registrationKey);

        return true;
    }

    public async Task<User?> LoginAsync(
        string email,
        string password,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email) ||
            string.IsNullOrWhiteSpace(password))
        {
            return null;
        }

        var user =
            await _userRepository.GetByEmailAsync(
                email,
                cancellationToken);

        if (user == null)
        {
            return null;
        }

        if (!user.IsActive)
        {
            return null;
        }

        if (!user.EmailVerified)
        {
            return null;
        }

        var passwordValid =
            BCrypt.Net.BCrypt.Verify(
                password,
                user.PasswordHash);

        if (!passwordValid)
        {
            return null;
        }

        return user;
    }

    private static string GetOtpKey(
        string email)
    {
        return $"CloudX:RegisterOtp:{email}";
    }

    private static string GetRegistrationKey(
        string email)
    {
        return $"CloudX:RegisterData:{email}";
    }

    private static string NormalizeEmail(
        string email)
    {
        return email
            .Trim()
            .ToLowerInvariant();
    }
}