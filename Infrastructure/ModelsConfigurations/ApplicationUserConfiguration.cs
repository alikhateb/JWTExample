using Domain.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Infrastructure.ModelsConfigurations;

public class ApplicationUserConfiguration : IEntityTypeConfiguration<ApplicationUser>
{
    public void Configure(EntityTypeBuilder<ApplicationUser> builder)
    {
        builder.Property(p => p.FirstName)
            .HasMaxLength(50)
            .IsRequired(true);

        builder.Property(p => p.LastName)
            .HasMaxLength(50)
            .IsRequired(true);

        builder.OwnsMany(p => p.RefreshTokens);
    }
}
