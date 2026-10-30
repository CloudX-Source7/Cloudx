
using CloudX.EntraID.Models;
using CloudX.Models;
using Microsoft.EntityFrameworkCore;

namespace CloudX.Data;

public class CloudDbContext : DbContext
{
    public CloudDbContext(
        DbContextOptions<CloudDbContext> options)
        : base(options)
    {
    }


    // ============================================================
    // EXISTING TABLES
    // ============================================================

    public DbSet<Customer> Customers =>
        Set<Customer>();

    public DbSet<CloudX.Models.AzureConnection> AzureConnections =>
        Set<CloudX.Models.AzureConnection>();

    public DbSet<AzureResource> AzureResources =>
        Set<AzureResource>();

    public DbSet<CloudX.Models.AzureCost> AzureCosts =>
        Set<CloudX.Models.AzureCost>();


    // ============================================================
    // USERS
    // ============================================================

    public DbSet<User> Users =>
        Set<User>();


    // ============================================================
    // ENTRA ID ACCESS LIFECYCLE
    // ============================================================

    public DbSet<AccessLifecycleAudit> AccessLifecycleAudits =>
        Set<AccessLifecycleAudit>();


    // ============================================================
    // COMPLIANCE
    // ============================================================

    public DbSet<AzureSubscriptionSelection> AzureSubscriptionSelections =>
    Set<AzureSubscriptionSelection>();
    // ============================================================
    // MODEL CONFIGURATION
    // ============================================================

    protected override void OnModelCreating(
        ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Automatically loads:
        // AzureCostConfiguration
        // AzureResourceConfiguration
        // ComplianceConfiguration
        // and any future IEntityTypeConfiguration<T> classes.
        modelBuilder.ApplyConfigurationsFromAssembly(
            typeof(CloudDbContext).Assembly);


        // ========================================================
        // USER CONFIGURATION
        // ========================================================

        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.Email)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(x => x.PasswordHash)
                .IsRequired();

            entity.Property(x => x.EmailVerified)
                .IsRequired();

            entity.Property(x => x.Role)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(x => x.CreatedAt)
                .IsRequired();

            entity.Property(x => x.IsActive)
                .IsRequired();

            // Unique email
            entity.HasIndex(x => x.Email)
                .IsUnique();
        });


        // ========================================================
        // CUSTOMER CONFIGURATION
        // ========================================================

        modelBuilder.Entity<Customer>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.HasOne(x => x.User)
                .WithMany()
                .HasForeignKey(x => x.UserId)
                .OnDelete(DeleteBehavior.Restrict);
        });


        // ========================================================
        // ACCESS LIFECYCLE AUDIT CONFIGURATION
        // ========================================================

        modelBuilder.Entity<AccessLifecycleAudit>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.TimestampUtc)
                .IsRequired();

            entity.Property(x => x.Action)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(x => x.Result)
                .IsRequired()
                .HasMaxLength(50);

            entity.Property(x => x.ActorName)
                .HasMaxLength(200);

            entity.Property(x => x.EntraTenantId)
                .HasMaxLength(100);

            entity.Property(x => x.TargetUserId)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(x => x.TargetDisplayName)
                .HasMaxLength(200);

            entity.Property(x => x.TargetUserPrincipalName)
                .HasMaxLength(320);

            entity.Property(x => x.Details)
                .HasMaxLength(2000);
        });
        // AZURE SUBSCRIPTION SELECTION CONFIGURATION
        modelBuilder.Entity<AzureSubscriptionSelection>(entity =>
        {
            entity.HasKey(x => x.Id);

            entity.Property(x => x.SubscriptionId)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(x => x.SelectedAt)
                .IsRequired();

            entity.HasOne(x => x.Customer)
                .WithMany()
                .HasForeignKey(x => x.CustomerId)
                .OnDelete(DeleteBehavior.Cascade);

            // Prevent selecting the same subscription twice for one customer.
            entity.HasIndex(x => new { x.CustomerId, x.SubscriptionId })
                .IsUnique();
        });
    }
}