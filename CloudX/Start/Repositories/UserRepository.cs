using CloudX.Data;
using CloudX.Models;
using Microsoft.EntityFrameworkCore;

namespace CloudX.Repositories;

public sealed class UserRepository : IUserRepository
{
    private readonly CloudDbContext _context;

    public UserRepository(CloudDbContext context)
    {
        _context = context;
    }

    // ============================================================
    // CHECK EMAIL
    // ============================================================

    public async Task<bool> EmailExistsAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return false;
        }

        var normalizedEmail =
            NormalizeEmail(email);

        return await _context
            .Set<User>()
            .AsNoTracking()
            .AnyAsync(
                user => user.Email == normalizedEmail,
                cancellationToken);
    }


    // ============================================================
    // GET USER BY EMAIL
    // ============================================================

    public async Task<User?> GetByEmailAsync(
        string email,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(email))
        {
            return null;
        }

        var normalizedEmail =
            NormalizeEmail(email);

        return await _context
            .Set<User>()
            .AsNoTracking()
            .FirstOrDefaultAsync(
                user => user.Email == normalizedEmail,
                cancellationToken);
    }


    // ============================================================
    // CREATE USER
    // ============================================================

    public async Task<User> CreateAsync(
        User user,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(user);

        user.Email =
            NormalizeEmail(user.Email);

        _context
            .Set<User>()
            .Add(user);

        await _context.SaveChangesAsync(
            cancellationToken);

        return user;
    }


    // ============================================================
    // NORMALIZE EMAIL
    // ============================================================

    private static string NormalizeEmail(
        string email)
    {
        return email
            .Trim()
            .ToLowerInvariant();
    }
}