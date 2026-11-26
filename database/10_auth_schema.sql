/* =============================================================================
   10_auth_schema.sql  (AuthDb)
   Run as: deployment account.

   Login, role, permission, session and audit data. Kept in a separate database
   from customer data (Guide 2.4, 3.2).

   Part A recreates the standard ASP.NET Core Identity tables (default schema,
   version 1) so Identity's built-in features can be used: PBKDF2 password
   hashing, lockout counters, TOTP authenticator keys and roles.
   NOTE for Phase 3: confirm the API's Identity model matches this schema with
   `dotnet ef migrations script`; the API maps to these tables and does not run
   migrations against AuthDb.

   Part B adds the project's own security tables: permissions, role-to-
   permission mapping, role-to-data-view mapping, sessions, audit log, search
   log and security alerts.
   ============================================================================= */
USE AuthDb;
GO

/* ===================== Part A: ASP.NET Core Identity ===================== */

IF OBJECT_ID(N'dbo.AspNetRoles', N'U') IS NULL
CREATE TABLE dbo.AspNetRoles (
    Id               NVARCHAR(450) NOT NULL CONSTRAINT PK_AspNetRoles PRIMARY KEY,
    Name             NVARCHAR(256) NULL,
    NormalizedName   NVARCHAR(256) NULL,
    ConcurrencyStamp NVARCHAR(MAX) NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'RoleNameIndex')
    CREATE UNIQUE INDEX RoleNameIndex ON dbo.AspNetRoles (NormalizedName) WHERE NormalizedName IS NOT NULL;
GO

IF OBJECT_ID(N'dbo.AspNetUsers', N'U') IS NULL
CREATE TABLE dbo.AspNetUsers (
    Id                   NVARCHAR(450)  NOT NULL CONSTRAINT PK_AspNetUsers PRIMARY KEY,
    -- [Guide §2.4] usernames 3-32 characters: letters, digits, '.' and '_'
    UserName             NVARCHAR(256)  NULL
        CONSTRAINT CK_AspNetUsers_UserName
        CHECK (UserName IS NULL OR (LEN(UserName) BETWEEN 3 AND 32 AND UserName NOT LIKE N'%[^a-zA-Z0-9._]%')),
    NormalizedUserName   NVARCHAR(256)  NULL,
    Email                NVARCHAR(256)  NULL,
    NormalizedEmail      NVARCHAR(256)  NULL,
    EmailConfirmed       BIT            NOT NULL,
    -- [Guide §2.4] PBKDF2-HMAC-SHA512 (600,000 iterations) hash with per-user salt,
    -- produced by Identity's PasswordHasher. Plain-text passwords never stored.
    -- Standard: OWASP ASVS 5.0 V11.4.2; OWASP Password Storage Cheat Sheet.
    PasswordHash         NVARCHAR(MAX)  NULL,
    SecurityStamp        NVARCHAR(MAX)  NULL,
    ConcurrencyStamp     NVARCHAR(MAX)  NULL,
    PhoneNumber          NVARCHAR(MAX)  NULL,
    PhoneNumberConfirmed BIT            NOT NULL,
    -- [Guide §2.4] TOTP MFA flag (required for Accounting, Privileged, UserAdmin)
    TwoFactorEnabled     BIT            NOT NULL,
    -- [Guide §2.5] lockout: 5 failures -> locked until LockoutEnd (15 minutes)
    LockoutEnd           DATETIMEOFFSET NULL,
    LockoutEnabled       BIT            NOT NULL,
    AccessFailedCount    INT            NOT NULL,
    -- ---- project columns ----
    -- [Guide §4.2] disabled on manager's request or after 90 days without login
    IsDisabled           BIT            NOT NULL CONSTRAINT DF_AspNetUsers_IsDisabled DEFAULT (0),
    LastLoginUtc         DATETIME2(0)   NULL,
    -- [Guide §2.2 / risk R4] search paused at the daily hard limit until unlocked
    SearchPausedUntilUtc DATETIME2(0)   NULL,
    CreatedUtc           DATETIME2(0)   NOT NULL CONSTRAINT DF_AspNetUsers_CreatedUtc DEFAULT (SYSUTCDATETIME())
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UserNameIndex')
    CREATE UNIQUE INDEX UserNameIndex ON dbo.AspNetUsers (NormalizedUserName) WHERE NormalizedUserName IS NOT NULL;
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'EmailIndex')
    CREATE INDEX EmailIndex ON dbo.AspNetUsers (NormalizedEmail);
GO

IF OBJECT_ID(N'dbo.AspNetRoleClaims', N'U') IS NULL
CREATE TABLE dbo.AspNetRoleClaims (
    Id         INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AspNetRoleClaims PRIMARY KEY,
    RoleId     NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetRoleClaims_AspNetRoles_RoleId REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE,
    ClaimType  NVARCHAR(MAX) NULL,
    ClaimValue NVARCHAR(MAX) NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AspNetRoleClaims_RoleId')
    CREATE INDEX IX_AspNetRoleClaims_RoleId ON dbo.AspNetRoleClaims (RoleId);
GO

IF OBJECT_ID(N'dbo.AspNetUserClaims', N'U') IS NULL
CREATE TABLE dbo.AspNetUserClaims (
    Id         INT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AspNetUserClaims PRIMARY KEY,
    UserId     NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetUserClaims_AspNetUsers_UserId REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE,
    ClaimType  NVARCHAR(MAX) NULL,
    ClaimValue NVARCHAR(MAX) NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AspNetUserClaims_UserId')
    CREATE INDEX IX_AspNetUserClaims_UserId ON dbo.AspNetUserClaims (UserId);
GO

IF OBJECT_ID(N'dbo.AspNetUserLogins', N'U') IS NULL
CREATE TABLE dbo.AspNetUserLogins (
    LoginProvider       NVARCHAR(450) NOT NULL,
    ProviderKey         NVARCHAR(450) NOT NULL,
    ProviderDisplayName NVARCHAR(MAX) NULL,
    UserId              NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetUserLogins_AspNetUsers_UserId REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE,
    CONSTRAINT PK_AspNetUserLogins PRIMARY KEY (LoginProvider, ProviderKey)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AspNetUserLogins_UserId')
    CREATE INDEX IX_AspNetUserLogins_UserId ON dbo.AspNetUserLogins (UserId);
GO

IF OBJECT_ID(N'dbo.AspNetUserRoles', N'U') IS NULL
CREATE TABLE dbo.AspNetUserRoles (
    UserId NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetUserRoles_AspNetUsers_UserId REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE,
    RoleId NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetUserRoles_AspNetRoles_RoleId REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE,
    CONSTRAINT PK_AspNetUserRoles PRIMARY KEY (UserId, RoleId)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AspNetUserRoles_RoleId')
    CREATE INDEX IX_AspNetUserRoles_RoleId ON dbo.AspNetUserRoles (RoleId);
-- [Guide §4.2] EXACTLY ONE ROLE PER USER, enforced by the database.
-- A user can never hold a data role and UserAdmin at the same time
-- (separation of duties, Guide 4.4).
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'UX_AspNetUserRoles_OneRolePerUser')
    CREATE UNIQUE INDEX UX_AspNetUserRoles_OneRolePerUser ON dbo.AspNetUserRoles (UserId);
GO

-- Identity stores the TOTP authenticator key here (LoginProvider
-- '[AspNetUserStore]', Name 'AuthenticatorKey'). Supports TOTP MFA (Guide 2.4).
-- Production hardening (not claimed in the guide): protect this value with
-- ASP.NET Core Data Protection so a stolen AuthDb does not reveal MFA secrets.
IF OBJECT_ID(N'dbo.AspNetUserTokens', N'U') IS NULL
CREATE TABLE dbo.AspNetUserTokens (
    UserId        NVARCHAR(450) NOT NULL
        CONSTRAINT FK_AspNetUserTokens_AspNetUsers_UserId REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE,
    LoginProvider NVARCHAR(450) NOT NULL,
    Name          NVARCHAR(450) NOT NULL,
    Value         NVARCHAR(MAX) NULL,
    CONSTRAINT PK_AspNetUserTokens PRIMARY KEY (UserId, LoginProvider, Name)
);
GO

/* ===================== Part B: project security tables ===================== */

/* ---- RBAC: permissions and role-to-permission mapping (Guide 4.1, 4.3) ----
   Roles say WHO a user is; permissions say WHAT they may do. The API checks
   permissions, not role names, so the access matrix lives in data and can be
   reviewed in one place. */
IF OBJECT_ID(N'dbo.Permissions', N'U') IS NULL
CREATE TABLE dbo.Permissions (
    PermissionId INT          NOT NULL CONSTRAINT PK_Permissions PRIMARY KEY,
    Code         VARCHAR(50)  NOT NULL CONSTRAINT UQ_Permissions_Code UNIQUE
        CONSTRAINT CK_Permissions_Code CHECK (Code NOT LIKE '%[^a-z.]%'),
    Description  NVARCHAR(200) NOT NULL
);
GO

IF OBJECT_ID(N'dbo.RolePermissions', N'U') IS NULL
CREATE TABLE dbo.RolePermissions (
    RoleId       NVARCHAR(450) NOT NULL
        CONSTRAINT FK_RolePermissions_Role REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE,
    PermissionId INT NOT NULL
        CONSTRAINT FK_RolePermissions_Permission REFERENCES dbo.Permissions (PermissionId),
    CONSTRAINT PK_RolePermissions PRIMARY KEY (RoleId, PermissionId)
);
GO

/* ---- Role-to-data-view mapping (Guide 4.3) ----
   Tells the API which CustomerDb view (and therefore which view-limited login)
   a role uses. UserAdmin has none: it can never read customer data. */
IF OBJECT_ID(N'dbo.RoleDataAccess', N'U') IS NULL
CREATE TABLE dbo.RoleDataAccess (
    RoleId           NVARCHAR(450) NOT NULL CONSTRAINT PK_RoleDataAccess PRIMARY KEY
        CONSTRAINT FK_RoleDataAccess_Role REFERENCES dbo.AspNetRoles (Id) ON DELETE CASCADE,
    DataViewName     SYSNAME     NULL
        CONSTRAINT CK_RoleDataAccess_View
        CHECK (DataViewName IS NULL OR DataViewName IN (N'vw_Normal', N'vw_Accounting', N'vw_Privileged')),
    -- name of the connection string in the API's .env (not the secret itself)
    ConnectionName   VARCHAR(50) NULL
        CONSTRAINT CK_RoleDataAccess_Conn
        CHECK (ConnectionName IS NULL OR ConnectionName IN ('CustomerNormal', 'CustomerAccounting', 'CustomerPrivileged')),
    CONSTRAINT CK_RoleDataAccess_Pair CHECK ((DataViewName IS NULL AND ConnectionName IS NULL)
                                          OR (DataViewName IS NOT NULL AND ConnectionName IS NOT NULL))
);
GO

/* ---- Sessions (Guide 2.4) ----
   Only the SHA-256 hash of the 256-bit session token is stored, so a stolen
   AuthDb cannot be used to hijack sessions.
   Standard: OWASP ASVS 5.0 V11.5.1 (CSPRNG, >= 128 bits). */
IF OBJECT_ID(N'dbo.Sessions', N'U') IS NULL
CREATE TABLE dbo.Sessions (
    SessionId         BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_Sessions PRIMARY KEY,
    UserId            NVARCHAR(450) NOT NULL
        CONSTRAINT FK_Sessions_User REFERENCES dbo.AspNetUsers (Id) ON DELETE CASCADE,
    TokenHash         BINARY(32)    NOT NULL CONSTRAINT UQ_Sessions_TokenHash UNIQUE,
    CreatedUtc        DATETIME2(0)  NOT NULL CONSTRAINT DF_Sessions_Created DEFAULT (SYSUTCDATETIME()),
    LastSeenUtc       DATETIME2(0)  NOT NULL CONSTRAINT DF_Sessions_LastSeen DEFAULT (SYSUTCDATETIME()),
    -- 8-hour absolute limit; 15-minute idle limit is checked against LastSeenUtc
    AbsoluteExpiryUtc DATETIME2(0)  NOT NULL,
    RevokedUtc        DATETIME2(0)  NULL,
    CONSTRAINT CK_Sessions_Expiry CHECK (AbsoluteExpiryUtc > CreatedUtc
                                         AND AbsoluteExpiryUtc <= DATEADD(HOUR, 8, CreatedUtc))
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Sessions_UserId')
    CREATE INDEX IX_Sessions_UserId ON dbo.Sessions (UserId);
GO

/* ---- Audit log (Guide 5): append-only ----
   Never stores passwords, card numbers, medical status or search names. */
IF OBJECT_ID(N'dbo.AuditLog', N'U') IS NULL
CREATE TABLE dbo.AuditLog (
    AuditId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
    OccurredUtc      DATETIME2(3)  NOT NULL CONSTRAINT DF_AuditLog_Occurred DEFAULT (SYSUTCDATETIME()),
    ActorUserId      NVARCHAR(450) NULL,          -- NULL for failed logins of unknown users
    Action           VARCHAR(30)   NOT NULL
        CONSTRAINT CK_AuditLog_Action CHECK (Action IN (
            'LoginSucceeded','LoginFailed','AccountLocked','MfaFailed','Logout',
            'CardRevealed','MedicalViewed','AccessDenied',
            'UserCreated','UserDisabled','RoleAssigned','PasswordReset','MfaReset','SearchUnlocked')),
    Outcome          VARCHAR(10)   NOT NULL
        CONSTRAINT CK_AuditLog_Outcome CHECK (Outcome IN ('Success','Denied','Failure')),
    TargetUserId     NVARCHAR(450) NULL,
    TargetCustomerId INT           NULL,
    -- [Guide §4.4] manager's approval reference, required for role changes
    ApprovalRef      NVARCHAR(50)  NULL,
    ClientIp         VARCHAR(45)   NULL,
    CONSTRAINT CK_AuditLog_RoleChangeHasApproval
        CHECK (Action <> 'RoleAssigned' OR Outcome <> 'Success' OR (ApprovalRef IS NOT NULL AND LEN(TRIM(ApprovalRef)) > 0)),
    -- [Guide §4.4] nobody changes their own account or role
    CONSTRAINT CK_AuditLog_NoSelfAdmin
        CHECK (Action NOT IN ('RoleAssigned','UserDisabled','PasswordReset','MfaReset')
               OR Outcome <> 'Success' OR ActorUserId IS NULL OR TargetUserId IS NULL OR ActorUserId <> TargetUserId)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AuditLog_Actor_Time')
    CREATE INDEX IX_AuditLog_Actor_Time ON dbo.AuditLog (ActorUserId, OccurredUtc);
GO

/* ---- Search log (Guide 2.2, risk R4): append-only, no names ----
   PrefixFingerprint = HMAC-SHA-256 (256-bit key) of the typed prefix, so the
   system can count distinct prefixes (alphabet-walking) without storing them. */
IF OBJECT_ID(N'dbo.SearchLog', N'U') IS NULL
CREATE TABLE dbo.SearchLog (
    SearchId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_SearchLog PRIMARY KEY,
    UserId            NVARCHAR(450) NOT NULL,
    OccurredUtc       DATETIME2(3)  NOT NULL CONSTRAINT DF_SearchLog_Occurred DEFAULT (SYSUTCDATETIME()),
    UsedWildcard      BIT           NOT NULL,
    PrefixLength      TINYINT       NOT NULL,
    PrefixFingerprint BINARY(32)    NULL,
    ResultCount       SMALLINT      NOT NULL CONSTRAINT CK_SearchLog_ResultCount CHECK (ResultCount BETWEEN 0 AND 50)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_SearchLog_User_Time')
    CREATE INDEX IX_SearchLog_User_Time ON dbo.SearchLog (UserId, OccurredUtc);
GO

/* ---- Security alerts (Guide 2.2, 4.4, 6) ---- */
IF OBJECT_ID(N'dbo.SecurityAlerts', N'U') IS NULL
CREATE TABLE dbo.SecurityAlerts (
    AlertId          BIGINT IDENTITY(1,1) NOT NULL CONSTRAINT PK_SecurityAlerts PRIMARY KEY,
    RaisedUtc        DATETIME2(0)  NOT NULL CONSTRAINT DF_SecurityAlerts_Raised DEFAULT (SYSUTCDATETIME()),
    UserId           NVARCHAR(450) NOT NULL,
    AlertType        VARCHAR(30)   NOT NULL
        CONSTRAINT CK_SecurityAlerts_Type CHECK (AlertType IN (
            'SearchSoftLimit','SearchHardLimit','AlphabetWalk','CardRevealLimit',
            'AccountLocked','RoleAssigned','PrivilegedRoleAssigned')),
    ResolvedByUserId NVARCHAR(450) NULL,
    ResolvedUtc      DATETIME2(0)  NULL,
    CONSTRAINT CK_SecurityAlerts_Resolved CHECK ((ResolvedByUserId IS NULL AND ResolvedUtc IS NULL)
                                              OR (ResolvedByUserId IS NOT NULL AND ResolvedUtc IS NOT NULL))
);
GO
