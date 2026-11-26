/*
 * File: CustomerAccess.cs
 * Implements: Guide §3.2, §4.3 each role is routed to its own database connection and view.
 * Controls:   R4
 */
using SBD.API.Common;
using SBD.API.Contexts;
using SBD.API.Models.CustomerDb;

namespace SBD.API.Services.Customers;

public class CustomerAccess(NormalViewContext normal, AccountingViewContext accounting, PrivilegedViewContext privileged)
{
    public const string NormalConnection = "CustomerNormal";
    public const string AccountingConnection = "CustomerAccounting";
    public const string PrivilegedConnection = "CustomerPrivileged";

    public NormalViewContext Normal => normal;
    public AccountingViewContext Accounting => accounting;
    public PrivilegedViewContext Privileged => privileged;

    // [Guide §3.2, §4.3] The user's data connection name comes from AuthDb (RoleDataAccess), never from the request; an unknown or missing name gets no data at all.
    // Why: fail-safe default. A role without a data view, such as UserAdmin, cannot be sent to a wider connection by mistake.
    // Standard: OWASP ASVS 5.0 V8.2.1; Saltzer & Schroeder (1975), fail-safe defaults.
    // Evidence: test Admin_CannotSearch (R4).
    public IQueryable<Locality>? Localities(string? connectionName) => connectionName switch
    {
        NormalConnection => normal.Localities,
        AccountingConnection => accounting.Localities,
        PrivilegedConnection => privileged.Localities,
        _ => null,
    };
}
