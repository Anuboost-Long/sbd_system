/*
 * File: CustomerViewContext.cs
 * Implements: Guide §3.2, §4.3 each role reads customers through a database login that can see only its own view.
 * Controls:   R4
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Models.CustomerDb;
using SBD.API.Models.CustomerDb.Views;

namespace SBD.API.Contexts;

// [Guide §3.2, §4.3] Each role reads through a database login that can only see its own view, so a coding mistake cannot reach other columns.
// Why: defence in depth; rights are enforced twice, in the API and in the database.
// Standard: OWASP ASVS 5.0 V8.2.3; Sandhu et al. (1996).
// Evidence: DB1-DB4 in verify_rbac.sql (R4).
public abstract class CustomerViewContext<TRow>(DbContextOptions options, string viewName) : DbContext(options)
    where TRow : class
{
    public DbSet<TRow> Customers => Set<TRow>();
    public DbSet<Locality> Localities => Set<Locality>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<TRow>().HasNoKey().ToView(viewName);
        modelBuilder.ApplyConfiguration(new LocalityMapping());
    }
}

public class NormalViewContext(DbContextOptions<NormalViewContext> options)
    : CustomerViewContext<NormalCustomerRow>(options, "vw_Normal");

public class AccountingViewContext(DbContextOptions<AccountingViewContext> options)
    : CustomerViewContext<AccountingCustomerRow>(options, "vw_Accounting");

public class PrivilegedViewContext(DbContextOptions<PrivilegedViewContext> options)
    : CustomerViewContext<PrivilegedCustomerRow>(options, "vw_Privileged");
