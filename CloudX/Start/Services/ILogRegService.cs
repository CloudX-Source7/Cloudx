using CloudX.DTOs;
using CloudX.Models;

namespace CloudX.Services;

public interface ILogRegService
{
    Task<bool> RegisterAsync(
        RegisterDto model,
        CancellationToken cancellationToken = default);

    Task<bool> VerifyOtpAsync(
        string email,
        string otp,
        CancellationToken cancellationToken = default);

    Task<User?> LoginAsync(
    string email,
    string password,
    CancellationToken cancellationToken = default);
}