# Database (SQL Server 2022)

Two databases, kept apart on purpose (Guide 3.2):

| Database     | Holds                                                                                                                     | API login                                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| `CustomerDb` | Localities, Customers (sensitive fields AES-256-GCM encrypted), 3 role views                                              | `app_view_normal` / `app_view_accounting` / `app_view_privileged` (one per view, read-only) |
| `AuthDb`     | ASP.NET Core Identity tables, Permissions, RolePermissions, RoleDataAccess, Sessions, AuditLog, SearchLog, SecurityAlerts | `app_identity`                                                                              |

## Run order

Passwords come from your `.env` via sqlcmd `-v` variables, never from the files.

```bash
set -a; source .env; set +a
S="sqlcmd -S localhost,1433 -U sa -P $MSSQL_SA_PASSWORD -C -b -I"

$S -i database/00_create_databases.sql
$S -i database/01_customer_schema.sql
$S -i database/02_customer_views.sql
$S -i database/03_customer_rbac.sql \
   -v APP_VIEW_NORMAL_PASSWORD="$APP_VIEW_NORMAL_PASSWORD" \
      APP_VIEW_ACCOUNTING_PASSWORD="$APP_VIEW_ACCOUNTING_PASSWORD" \
      APP_VIEW_PRIVILEGED_PASSWORD="$APP_VIEW_PRIVILEGED_PASSWORD" \
      APP_SEED_PASSWORD="$APP_SEED_PASSWORD"
$S -i database/04_seed_localities.sql
$S -i database/10_auth_schema.sql
$S -i database/11_auth_rbac_seed.sql -v APP_IDENTITY_PASSWORD="$APP_IDENTITY_PASSWORD"

# evidence for Appendix B: every line should say PASS
$S -i database/verify_rbac.sql
```

All scripts are safe to re-run (they check before creating).

## Role → permission matrix (from `11_auth_rbac_seed.sql`)

| Permission                                                                       |  Normal   |  Accounting   |  Privileged   | UserAdmin |
| -------------------------------------------------------------------------------- | :-------: | :-----------: | :-----------: | :-------: |
| customer.search                                                                  |     ✔     |       ✔       |       ✔       |           |
| customer.view.contact                                                            |     ✔     |       ✔       |       ✔       |           |
| customer.view.card.masked                                                        |           |       ✔       |       ✔       |           |
| customer.card.reveal                                                             |           |       ✔       |       ✔       |           |
| customer.view.medical                                                            |           |               |       ✔       |           |
| user.create / disable / role.assign / password.reset / mfa.reset / search.unlock |           |               |               |     ✔     |
| Customer data view                                                               | vw_Normal | vw_Accounting | vw_Privileged |   none    |

## Rules the database enforces (even if the API had a bug)

| Rule                                                          | How                                              | Test      |
| ------------------------------------------------------------- | ------------------------------------------------ | --------- |
| Search logins can't read the base table or other roles' views | GRANT on own view only, DENY on `Customers`      | DB1–DB4   |
| Normal view has no card or medical columns                    | View definition                                  | DB5       |
| Bad names rejected                                            | CHECK constraint                                 | DB-V      |
| UserAdmin never gets customer permissions (and the reverse)   | Trigger `trg_RolePermissions_SeparationOfDuties` | DB7       |
| Exactly one role per user                                     | Unique index on `AspNetUserRoles.UserId`         | DB8       |
| Logs can't be edited or deleted by the API                    | DENY UPDATE, DELETE                              | DB9       |
| API can't change the permission matrix                        | DENY INSERT, UPDATE, DELETE                      | DB10      |
| Role change needs approval ref; no self-change                | CHECK on `AuditLog`                              | DB11–DB12 |

**API note (Phase 5):** DB11/DB12 check the audit row, so the API must write the role change and its audit row in **one transaction**. That way a role change with no valid audit row is rolled back.

**Identity note (Phase 3):** the API maps to these tables and does not run EF migrations against AuthDb. Compare with `dotnet ef migrations script` once the Identity model is in place.
