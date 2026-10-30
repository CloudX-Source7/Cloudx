using CloudX.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace CloudX.Data.Configurations;

public class AzureResourceConfiguration
    : IEntityTypeConfiguration<AzureResource>
{
    public void Configure(
        EntityTypeBuilder<AzureResource> builder)
    {
        builder.HasKey(x => x.Id);

        builder.HasIndex(x => new
        {
            x.CustomerId,
            x.AzureResourceId
        })
        .IsUnique();

        builder.Property(x => x.AzureResourceId)
            .IsRequired();

        builder.Property(x => x.Name)
            .IsRequired();

        builder.Property(x => x.Type)
            .IsRequired();

        builder.Property(x => x.SubscriptionId)
            .IsRequired();

        builder.HasOne(x => x.Customer)
            .WithMany()
            .HasForeignKey(x => x.CustomerId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}