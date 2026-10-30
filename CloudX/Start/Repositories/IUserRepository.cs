using CloudX.Models;

namespace CloudX.Repositories;

public interface IUserRepository
{
    Task<bool> EmailExistsAsync(
        string email,
        CancellationToken cancellationToken = default);

    Task<User?> GetByEmailAsync(
        string email,
        CancellationToken cancellationToken = default);

    Task<User> CreateAsync(
        User user,
        CancellationToken cancellationToken = default);
}