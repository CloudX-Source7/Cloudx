using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using AzureCostModel = CloudX.Models.AzureCost;

namespace CloudX.Data.Configurations;

public class AzureCostConfiguration
    : IEntityTypeConfiguration<AzureCostModel>
{
    public void Configure(
        EntityTypeBuilder<AzureCostModel> builder)
    {
        builder.HasKey(x => x.Id);

        builder.HasIndex(x => new
        {
            x.CustomerId,
            x.AzureResourceId,
            x.Date
        })
        .IsUnique();

        builder.Property(x => x.AzureResourceId)
            .IsRequired();

        builder.Property(x => x.ResourceName)
            .IsRequired();

        builder.Property(x => x.ResourceType)
            .IsRequired();

        builder.Property(x => x.Cost)
            .HasPrecision(18, 4);

        builder.Property(x => x.Currency)
            .IsRequired();

        builder.HasOne(x => x.Customer)
            .WithMany()
            .HasForeignKey(x => x.CustomerId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}