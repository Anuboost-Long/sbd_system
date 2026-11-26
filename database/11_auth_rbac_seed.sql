/* =============================================================================
   11_auth_rbac_seed.sql  (AuthDb)
   Run as: deployment account, with sqlcmd variable APP_IDENTITY_PASSWORD
           (taken from .env, never written in this file).

   1. Separation-of-duties guard on the role -> permission matrix
   2. Roles, permissions and the role -> permission matrix
   3. Role -> customer data view mapping
   4. app_identity login (the API's AuthDb login) with least privilege
   ============================================================================= */
USE AuthDb;
GO

/* ---- 1. Separation of duties (Guide 4.4; ISO/IEC 27001:2022 A.5.3) ----
   UserAdmin may never hold a customer.* permission, and the data roles may
   never hold a user.* permission. Enforced by the database, so a mistake in
   the API or a manual INSERT cannot break it. */
CREATE OR ALTER TRIGGER dbo.trg_RolePermissions_SeparationOfDuties
ON dbo.RolePermissions
AFTER INSERT, UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    IF EXISTS (
        SELECT 1
        FROM inserted i
        JOIN dbo.AspNetRoles r ON r.Id = i.RoleId
        JOIN dbo.Permissions p ON p.PermissionId = i.PermissionId
        WHERE (r.NormalizedName = N'USERADMIN' AND p.Code LIKE 'customer.%')
           OR (r.NormalizedName <> N'USERADMIN' AND p.Code LIKE 'user.%')
    )
    BEGIN
        THROW 51000, 'Separation of duties: UserAdmin cannot hold customer permissions and data roles cannot hold user-admin permissions.', 1;
    END
END;
GO

/* ---- 2a. Roles (fixed IDs so the API and tests can refer to them) ---- */
MERGE dbo.AspNetRoles AS t
USING (VALUES
    (N'11111111-0000-0000-0000-000000000001', N'Normal',     N'NORMAL'),
    (N'11111111-0000-0000-0000-000000000002', N'Accounting', N'ACCOUNTING'),
    (N'11111111-0000-0000-0000-000000000003', N'Privileged', N'PRIVILEGED'),
    (N'11111111-0000-0000-0000-000000000004', N'UserAdmin',  N'USERADMIN')
) AS s (Id, Name, NormalizedName)
ON t.Id = s.Id
WHEN MATCHED THEN UPDATE SET Name = s.Name, NormalizedName = s.NormalizedName
WHEN NOT MATCHED THEN INSERT (Id, Name, NormalizedName, ConcurrencyStamp)
                      VALUES (s.Id, s.Name, s.NormalizedName, CONVERT(NVARCHAR(36), NEWID()));
GO

/* ---- 2b. Permissions ---- */
MERGE dbo.Permissions AS t
USING (VALUES
    (1,  'customer.search',           N'Search customers by name or phone'),
    (2,  'customer.view.contact',     N'See name, address and phone'),
    (3,  'customer.view.card.masked', N'See last 4 card digits only'),
    (4,  'customer.card.reveal',      N'Reveal full card number (logged, daily limit 20)'),
    (5,  'customer.view.medical',     N'See medical status (logged)'),
    (20, 'user.create',               N'Create staff accounts'),
    (21, 'user.disable',              N'Disable staff accounts'),
    (22, 'user.role.assign',          N'Assign a role (approval reference required)'),
    (23, 'user.password.reset',       N'Reset a staff password'),
    (24, 'user.mfa.reset',            N'Reset a staff MFA authenticator'),
    (25, 'user.search.unlock',        N'Unlock search after the daily hard limit')
) AS s (PermissionId, Code, Description)
ON t.PermissionId = s.PermissionId
WHEN MATCHED THEN UPDATE SET Code = s.Code, Description = s.Description
WHEN NOT MATCHED THEN INSERT (PermissionId, Code, Description) VALUES (s.PermissionId, s.Code, s.Description);
GO

/* ---- 2c. Role -> permission matrix (Guide 4.1 access table) ----
                      search contact card4 reveal medical | user.*
   Normal               Y      Y       -      -      -    |   -
   Accounting           Y      Y       Y      Y      -    |   -
   Privileged           Y      Y       Y      Y      Y    |   -
   UserAdmin            -      -       -      -      -    |   Y
   Privileged = Accounting + medical status (Guide 4.1). */
MERGE dbo.RolePermissions AS t
USING (VALUES
    (N'11111111-0000-0000-0000-000000000001', 1),
    (N'11111111-0000-0000-0000-000000000001', 2),
    (N'11111111-0000-0000-0000-000000000002', 1),
    (N'11111111-0000-0000-0000-000000000002', 2),
    (N'11111111-0000-0000-0000-000000000002', 3),
    (N'11111111-0000-0000-0000-000000000002', 4),
    (N'11111111-0000-0000-0000-000000000003', 1),
    (N'11111111-0000-0000-0000-000000000003', 2),
    (N'11111111-0000-0000-0000-000000000003', 3),
    (N'11111111-0000-0000-0000-000000000003', 4),
    (N'11111111-0000-0000-0000-000000000003', 5),
    (N'11111111-0000-0000-0000-000000000004', 20),
    (N'11111111-0000-0000-0000-000000000004', 21),
    (N'11111111-0000-0000-0000-000000000004', 22),
    (N'11111111-0000-0000-0000-000000000004', 23),
    (N'11111111-0000-0000-0000-000000000004', 24),
    (N'11111111-0000-0000-0000-000000000004', 25)
) AS s (RoleId, PermissionId)
ON t.RoleId = s.RoleId AND t.PermissionId = s.PermissionId
WHEN NOT MATCHED BY TARGET THEN INSERT (RoleId, PermissionId) VALUES (s.RoleId, s.PermissionId)
WHEN NOT MATCHED BY SOURCE THEN DELETE;   -- the matrix above is the single source of truth
GO

/* ---- 3. Role -> customer data view (Guide 4.3) ---- */
MERGE dbo.RoleDataAccess AS t
USING (VALUES
    (N'11111111-0000-0000-0000-000000000001', N'vw_Normal',     'CustomerNormal'),
    (N'11111111-0000-0000-0000-000000000002', N'vw_Accounting', 'CustomerAccounting'),
    (N'11111111-0000-0000-0000-000000000003', N'vw_Privileged', 'CustomerPrivileged'),
    (N'11111111-0000-0000-0000-000000000004', NULL,             NULL)   -- no customer data
) AS s (RoleId, DataViewName, ConnectionName)
ON t.RoleId = s.RoleId
WHEN MATCHED THEN UPDATE SET DataViewName = s.DataViewName, ConnectionName = s.ConnectionName
WHEN NOT MATCHED THEN INSERT (RoleId, DataViewName, ConnectionName) VALUES (s.RoleId, s.DataViewName, s.ConnectionName);
GO

/* ---- 4. app_identity: the API's only login for AuthDb (Guide 3.2) ---- */
USE master;
GO
IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = N'app_identity')
    CREATE LOGIN app_identity WITH PASSWORD = N'$(APP_IDENTITY_PASSWORD)',
        DEFAULT_DATABASE = AuthDb, CHECK_POLICY = ON;
GO
USE AuthDb;
GO
IF NOT EXISTS (SELECT 1 FROM sys.database_principals WHERE name = N'app_identity')
    CREATE USER app_identity FOR LOGIN app_identity;
GO

-- Identity tables: the API reads and maintains accounts, roles, tokens
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.AspNetUsers      TO app_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.AspNetUserRoles  TO app_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.AspNetUserClaims TO app_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.AspNetUserLogins TO app_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.AspNetUserTokens TO app_identity;
GRANT SELECT, INSERT, UPDATE, DELETE ON dbo.Sessions         TO app_identity;
GRANT SELECT, INSERT, UPDATE         ON dbo.SecurityAlerts   TO app_identity;

-- RBAC matrix is READ-ONLY to the API: only deployment scripts change it
GRANT SELECT ON dbo.AspNetRoles      TO app_identity;
GRANT SELECT ON dbo.AspNetRoleClaims TO app_identity;
GRANT SELECT ON dbo.Permissions      TO app_identity;
GRANT SELECT ON dbo.RolePermissions  TO app_identity;
GRANT SELECT ON dbo.RoleDataAccess   TO app_identity;
DENY INSERT, UPDATE, DELETE ON dbo.AspNetRoles      TO app_identity;
DENY INSERT, UPDATE, DELETE ON dbo.AspNetRoleClaims TO app_identity;
DENY INSERT, UPDATE, DELETE ON dbo.Permissions      TO app_identity;
DENY INSERT, UPDATE, DELETE ON dbo.RolePermissions  TO app_identity;
DENY INSERT, UPDATE, DELETE ON dbo.RoleDataAccess   TO app_identity;

-- Logs are APPEND-ONLY: the API can add and read, never edit or delete
-- (Guide 5; OWASP ASVS 5.0 V16 security logging)
GRANT SELECT, INSERT ON dbo.AuditLog  TO app_identity;
GRANT SELECT, INSERT ON dbo.SearchLog TO app_identity;
DENY UPDATE, DELETE  ON dbo.AuditLog  TO app_identity;
DENY UPDATE, DELETE  ON dbo.SearchLog TO app_identity;
GO
