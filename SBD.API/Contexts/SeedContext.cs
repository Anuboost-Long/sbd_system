using Microsoft.EntityFrameworkCore;
using SBD.API.Models.CustomerDb;

namespace SBD.API.Contexts;

public class SeedContext(DbContextOptions<SeedContext> options) : DbContext(options)
{
    public DbSet<Locality> Localities => Set<Locality>();
    public DbSet<Customer> Customers => Set<Customer>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ApplyConfiguration(new LocalityMapping());

        modelBuilder.Entity<Customer>(customer =>
        {
            customer.Property(c => c.FirstName).HasMaxLength(50);
            customer.Property(c => c.LastName).HasMaxLength(50);
            customer.Property(c => c.Unit).HasMaxLength(10);
            customer.Property(c => c.Street).HasMaxLength(60);
            customer.Property(c => c.Phone).HasMaxLength(16).IsUnicode(false);
            customer.Property(c => c.MedicalStatusEnc).HasMaxLength(48).IsUnicode(false);
            customer.Property(c => c.CardNumberEnc).HasMaxLength(80).IsUnicode(false);
            customer.Property(c => c.CardLast4).HasColumnType("char(4)");
            customer.Property(c => c.CardExpiryEnc).HasMaxLength(64).IsUnicode(false);
            customer.HasOne(c => c.Locality).WithMany().HasForeignKey(c => c.LocalityId).OnDelete(DeleteBehavior.Restrict);
        });
    }
}
