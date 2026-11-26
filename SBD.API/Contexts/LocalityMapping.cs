using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using SBD.API.Models.CustomerDb;

namespace SBD.API.Contexts;

public class LocalityMapping : IEntityTypeConfiguration<Locality>
{
    public void Configure(EntityTypeBuilder<Locality> locality)
    {
        locality.Property(l => l.Suburb).HasMaxLength(46);
        locality.Property(l => l.State).HasMaxLength(3).IsUnicode(false);
        locality.Property(l => l.Postcode).HasColumnType("char(4)");
    }
}
