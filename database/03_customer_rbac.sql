/* =============================================================================
   03_customer_rbac.sql  (server logins + CustomerDb roles and permissions)
   Run as: deployment account, through scripts/setup_db.sh, which passes the
   passwords below from the .env file as sqlcmd variables. No password is
   written in this file (Guide 3.2, risk R7).

   [Guide §3.2 / 4.3] Database-level RBAC:
     - Permissions are granted to DATABASE ROLES, never directly to logins.
     - Each application search login is a member of exactly one role and can
       read only its own view. Reading the base table is explicitly denied.
     - Human access (data maintenance, IT read-only) uses separate roles; those
       users see card and medical fields only as ciphertext, because the
       encryption key exists only in the application (Guide 3.3).
   Standard: OWASP ASVS 5.0 V8.2.1 / V8.2.3 (explicit, least-privilege access);
             ISO/IEC 27001:2022 access control; Saltzer & Schroeder (1975).
   ============================================================================= */

/* ---------------------------------------------------------------------------
   1. Server logins (application service accounts)
      CHECK_POLICY = ON applies the server's password policy.
   --------------------------------------------------------------------------- */
USE master;
GO

IF SUSER_ID(N'app_view_normal') IS NULL
    CREATE LOGIN app_view_normal     WITH PASSWORD = N'$(APP_VIEW_NORMAL_PASSWORD)',
        DEFAULT_DATABASE = CustomerDb, CHECK_POLICY = ON;
IF SUSER_ID(N'app_view_accounting') IS NULL
    CREATE LOGIN app_view_accounting WITH PASSWORD = N'$(APP_VIEW_ACCOUNTING_PASSWORD)',
        DEFAULT_DATABASE = CustomerDb, CHECK_POLICY = ON;
IF SUSER_ID(N'app_view_privileged') IS NULL
    CREATE LOGIN app_view_privileged WITH PASSWORD = N'$(APP_VIEW_PRIVILEGED_PASSWORD)',
        DEFAULT_DATABASE = CustomerDb, CHECK_POLICY = ON;
-- Used only by the API's seed command to load synthetic customers
IF SUSER_ID(N'app_seed') IS NULL
    CREATE LOGIN app_seed            WITH PASSWORD = N'$(APP_SEED_PASSWORD)',
        DEFAULT_DATABASE = CustomerDb, CHECK_POLICY = ON;
GO

/* ---------------------------------------------------------------------------
   2. CustomerDb roles (what each role may do)
   --------------------------------------------------------------------------- */
USE CustomerDb;
GO

IF DATABASE_PRINCIPAL_ID(N'rl_search_normal')     IS NULL CREATE ROLE rl_search_normal;
IF DATABASE_PRINCIPAL_ID(N'rl_search_accounting') IS NULL CREATE ROLE rl_search_accounting;
IF DATABASE_PRINCIPAL_ID(N'rl_search_privileged') IS NULL CREATE ROLE rl_search_privileged;
IF DATABASE_PRINCIPAL_ID(N'rl_data_maintenance')  IS NULL CREATE ROLE rl_data_maintenance;
IF DATABASE_PRINCIPAL_ID(N'rl_it_readonly')       IS NULL CREATE ROLE rl_it_readonly;
GO

-- Search roles: own view + the non-sensitive Localities list (for the
-- suburb dropdown and the locality check). Nothing else.
GRANT SELECT ON dbo.vw_Normal     TO rl_search_normal;
GRANT SELECT ON dbo.vw_Accounting TO rl_search_accounting;
GRANT SELECT ON dbo.vw_Privileged TO rl_search_privileged;
GRANT SELECT ON dbo.Localities    TO rl_search_normal, rl_search_accounting, rl_search_privileged;

-- Explicit DENY on the base table: even if someone later grants broader
-- rights by mistake, DENY wins in SQL Server (fail-safe default).
DENY SELECT, INSERT, UPDATE, DELETE ON dbo.Customers
    TO rl_search_normal, rl_search_accounting, rl_search_privileged;
-- Search roles may never change locality data either
DENY INSERT, UPDATE, DELETE ON dbo.Localities
    TO rl_search_normal, rl_search_accounting, rl_search_privileged;

-- Data maintenance (named staff + the seed account): change customer records,
-- no schema changes. Sees sensitive fields only as ciphertext.
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Customers TO rl_data_maintenance;
GRANT SELECT ON dbo.Localities TO rl_data_maintenance;

-- IT read-only (named staff): ad-hoc SELECT queries; ciphertext only.
GRANT SELECT ON dbo.Customers  TO rl_it_readonly;
GRANT SELECT ON dbo.Localities TO rl_it_readonly;
GO

/* ---------------------------------------------------------------------------
   3. Database users and role membership (one role each)
   --------------------------------------------------------------------------- */
IF DATABASE_PRINCIPAL_ID(N'app_view_normal')     IS NULL CREATE USER app_view_normal     FOR LOGIN app_view_normal;
IF DATABASE_PRINCIPAL_ID(N'app_view_accounting') IS NULL CREATE USER app_view_accounting FOR LOGIN app_view_accounting;
IF DATABASE_PRINCIPAL_ID(N'app_view_privileged') IS NULL CREATE USER app_view_privileged FOR LOGIN app_view_privileged;
IF DATABASE_PRINCIPAL_ID(N'app_seed')            IS NULL CREATE USER app_seed            FOR LOGIN app_seed;
GO

ALTER ROLE rl_search_normal     ADD MEMBER app_view_normal;
ALTER ROLE rl_search_accounting ADD MEMBER app_view_accounting;
ALTER ROLE rl_search_privileged ADD MEMBER app_view_privileged;
ALTER ROLE rl_data_maintenance  ADD MEMBER app_seed;
GO

/* Human staff accounts are created at deployment and added to
   rl_data_maintenance or rl_it_readonly. They are personal (never shared)
   and audited with SQL Server Audit (Guide 3.2, 4.2). Not created here. */
