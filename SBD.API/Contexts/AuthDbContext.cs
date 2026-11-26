using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SBD.API.Models.AuthDb;

namespace SBD.API.Contexts;

public class AuthDbContext(DbContextOptions<AuthDbContext> options) : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<Permission> Permissions => Set<Permission>();
    public DbSet<RolePermission> RolePermissions => Set<RolePermission>();
    public DbSet<RoleDataAccess> RoleDataAccesses => Set<RoleDataAccess>();
    public DbSet<Session> Sessions => Set<Session>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<SearchLog> SearchLogs => Set<SearchLog>();
    public DbSet<SecurityAlert> SecurityAlerts => Set<SecurityAlert>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<ApplicationUser>(user =>
        {
            user.Property(u => u.IsDisabled).HasDefaultValue(false);
            user.Property(u => u.CreatedUtc).HasDefaultValueSql("SYSUTCDATETIME()");
        });

        modelBuilder.Entity<IdentityUserRole<string>>().HasIndex(ur => ur.UserId).IsUnique();

        modelBuilder.Entity<Permission>(permission =>
        {
            permission.Property(p => p.PermissionId).ValueGeneratedNever();
            permission.Property(p => p.Code).HasMaxLength(50).IsUnicode(false);
            permission.Property(p => p.Description).HasMaxLength(200);
            permission.HasIndex(p => p.Code).IsUnique();
        });

        modelBuilder.Entity<RolePermission>(rolePermission =>
        {
            rolePermission.HasKey(rp => new { rp.RoleId, rp.PermissionId });
            rolePermission.HasOne(rp => rp.Role).WithMany().HasForeignKey(rp => rp.RoleId);
            rolePermission.HasOne(rp => rp.Permission).WithMany().HasForeignKey(rp => rp.PermissionId);
        });

        modelBuilder.Entity<RoleDataAccess>(access =>
        {
            access.ToTable("RoleDataAccess");
            access.HasKey(a => a.RoleId);
            access.HasOne(a => a.Role).WithOne().HasForeignKey<RoleDataAccess>(a => a.RoleId);
            access.Property(a => a.DataViewName).HasColumnType("sysname");
            access.Property(a => a.ConnectionName).HasMaxLength(50).IsUnicode(false);
        });

        modelBuilder.Entity<Session>(session =>
        {
            session.Property(s => s.UserId).HasMaxLength(450);
            session.Property(s => s.TokenHash).HasColumnType("binary(32)");
            session.HasIndex(s => s.TokenHash).IsUnique();
            session.HasOne(s => s.User).WithMany().HasForeignKey(s => s.UserId);
        });

        modelBuilder.Entity<AuditLog>(audit =>
        {
            audit.ToTable("AuditLog");
            audit.HasKey(a => a.AuditId);
            audit.Property(a => a.OccurredUtc).HasColumnType("datetime2(3)");
            audit.Property(a => a.ActorUserId).HasMaxLength(450);
            audit.Property(a => a.Action).HasConversion<string>().HasMaxLength(30).IsUnicode(false);
            audit.Property(a => a.Outcome).HasConversion<string>().HasMaxLength(10).IsUnicode(false);
            audit.Property(a => a.TargetUserId).HasMaxLength(450);
            audit.Property(a => a.ApprovalRef).HasMaxLength(50);
            audit.Property(a => a.ClientIp).HasMaxLength(45).IsUnicode(false);
        });

        modelBuilder.Entity<SearchLog>(search =>
        {
            search.ToTable("SearchLog");
            search.HasKey(s => s.SearchId);
            search.Property(s => s.UserId).HasMaxLength(450);
            search.Property(s => s.OccurredUtc).HasColumnType("datetime2(3)");
            search.Property(s => s.PrefixFingerprint).HasColumnType("binary(32)");
        });

        modelBuilder.Entity<SecurityAlert>(alert =>
        {
            alert.HasKey(a => a.AlertId);
            alert.Property(a => a.UserId).HasMaxLength(450);
            alert.Property(a => a.AlertType).HasConversion<string>().HasMaxLength(30).IsUnicode(false);
            alert.Property(a => a.ResolvedByUserId).HasMaxLength(450);
        });
    }
}
