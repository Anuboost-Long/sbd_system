# Database model spec (for EF Core models)

Two databases: **CustomerDb** (customer data) and **AuthDb** (logins, roles, logs). Guide 3.2.
Each field lists its SQL type, its C# type, whether it's required, the validation rule and the report section it comes from.

---

## CustomerDb

### 1. `Locality` (table `Localities`): §2.1, §3.1

The suburb, state and postcode are linked, so they're picked as one unit.

| Field      | SQL type        | C# type  | Req | Rule                                       | Source                       |
| ---------- | --------------- | -------- | --- | ------------------------------------------ | ---------------------------- |
| LocalityId | INT IDENTITY PK | `int`    | ✔   | auto                                       |                              |
| Suburb     | NVARCHAR(46)    | `string` | ✔   | letters, space, `'` `-` only; max 46       | WA DPC 2022 address standard |
| State      | VARCHAR(3)      | `string` | ✔   | one of NSW, VIC, QLD, SA, WA, TAS, NT, ACT | §2.1                         |
| Postcode   | CHAR(4)         | `string` | ✔   | exactly 4 digits (`^\d{4}$`)               | §2.1                         |

Unique: (Suburb, State, Postcode).

### 2. `Customer` (table `Customers`): §3.1

| Field            | SQL type            | C# type   | Req | Rule                                                                                 | Source     |
| ---------------- | ------------------- | --------- | --- | ------------------------------------------------------------------------------------ | ---------- |
| CustomerId       | INT IDENTITY PK     | `int`     | ✔   | auto                                                                                 |            |
| FirstName        | NVARCHAR(50)        | `string`  | ✔   | 1–50; Unicode letters, space, `-`, `'`; NFC-normalised                               | §2.1, §3.1 |
| LastName         | NVARCHAR(50)        | `string`  | ✔   | same as FirstName                                                                    | §2.1, §3.1 |
| Unit             | NVARCHAR(10)        | `string?` |     | max 10; letters, digits, `/` `-`                                                     | §2.1, §3.1 |
| Street           | NVARCHAR(60)        | `string`  | ✔   | max 60; letters, digits, space, `-`, `'`, `.`                                        | §2.1, §3.1 |
| LocalityId       | INT FK → Localities | `int`     | ✔   | must exist                                                                           | §2.1, §3.1 |
| Phone            | VARCHAR(16)         | `string`  | ✔   | E.164: `+` and 7–15 digits; length checked per country code (in-house table)         | §2.1, §3.1 |
| MedicalStatusEnc | VARCHAR(48)         | `string`  | ✔   | **encrypted** code 1–6, stored `v1:<Base64>`                                         | §3.1, §3.3 |
| CardNumberEnc    | VARCHAR(80)         | `string`  | ✔   | **encrypted**; plain value 10–19 digits + Luhn check, padded to 19 before encrypting | §3.1, §3.3 |
| CardLast4        | CHAR(4)             | `string`  | ✔   | 4 digits, plain (for masked display)                                                 | §3.1, §3.3 |
| CardExpiryEnc    | VARCHAR(64)         | `string`  | ✔   | **encrypted** MM/YY; month 01–12                                                     | §3.1, §3.3 |

Indexes: LastName, FirstName, Phone (for search).

**Medical status codes** (C# `enum MedicalStatus : byte`):
1 Sick · 2 Healthy · 3 Cancer · 4 Deceased · 5 Flu · 6 Covid

**Encryption** (§3.3): AES-256-GCM, 12-byte nonce, 16-byte tag, associated data = `CustomerId + column name`.
Stored as `v1:` + Base64(nonce ‖ ciphertext ‖ tag). The key comes from `.env` (`FieldEncryption__Key`).

### 3. Role views (read-only, keyless in EF): Guide 4.3

One DTO per view; each role's connection can read only its own view.

| Field                                         | vw_Normal | vw_Accounting | vw_Privileged |
| --------------------------------------------- | :-------: | :-----------: | :-----------: |
| CustomerId, FirstName, LastName, Unit, Street |     ✔     |       ✔       |       ✔       |
| Suburb, State, Postcode (joined)              |     ✔     |       ✔       |       ✔       |
| Phone                                         |     ✔     |       ✔       |       ✔       |
| CardLast4                                     |           |       ✔       |       ✔       |
| CardNumberEnc, CardExpiryEnc (reveal)         |           |       ✔       |       ✔       |
| MedicalStatusEnc                              |           |               |       ✔       |

EF: `modelBuilder.Entity<NormalCustomerView>().HasNoKey().ToView("vw_Normal");` (and the same for the other two).

---

## AuthDb

### 4. `ApplicationUser : IdentityUser`: Guide 2.4, 4.2

Identity already gives you Id, UserName, PasswordHash (PBKDF2-HMAC-SHA512, 600,000 iterations), TwoFactorEnabled, LockoutEnd, AccessFailedCount, SecurityStamp and the rest. **Add only these:**

| Field                | SQL type      | C# type     | Req | Rule                                                     | Source  |
| -------------------- | ------------- | ----------- | --- | -------------------------------------------------------- | ------- |
| IsDisabled           | BIT default 0 | `bool`      | ✔   | set on a manager request or after 90 days without login  | 4.2     |
| LastLoginUtc         | DATETIME2     | `DateTime?` |     | updated on each successful login                         | 4.2     |
| SearchPausedUntilUtc | DATETIME2     | `DateTime?` |     | set at the daily hard limit; cleared by UserAdmin unlock | 2.2, R4 |
| CreatedUtc           | DATETIME2     | `DateTime`  | ✔   | default now                                              |         |

UserName rule: 3–32 characters, letters, digits, `.` `_`.
Identity settings: lockout after 5 failures for 15 min; password min 15 (8 if MFA is on), max ≥64, no composition rules.

### 5. `IdentityRole`: Guide 4.1

Seeded: **Normal, Accounting, Privileged, UserAdmin**. One role per user (unique index on `AspNetUserRoles.UserId`).

### 6. `Permission`: Guide 4.1

| Field        | SQL type           | C# type  | Req | Rule                                       |
| ------------ | ------------------ | -------- | --- | ------------------------------------------ |
| PermissionId | INT PK             | `int`    | ✔   | fixed IDs                                  |
| Code         | VARCHAR(50) unique | `string` | ✔   | lowercase and dots, e.g. `customer.search` |
| Description  | NVARCHAR(200)      | `string` | ✔   |                                            |

Codes: `customer.search`, `customer.view.contact`, `customer.view.card.masked`, `customer.card.reveal`, `customer.view.medical`, `user.create`, `user.disable`, `user.role.assign`, `user.password.reset`, `user.mfa.reset`, `user.search.unlock`.

### 7. `RolePermission` (join): Guide 4.1, 4.4

| Field        | SQL type         | C# type  |
| ------------ | ---------------- | -------- |
| RoleId       | NVARCHAR(450) FK | `string` |
| PermissionId | INT FK           | `int`    |

PK (RoleId, PermissionId). Rule: UserAdmin never gets `customer.*`; data roles never get `user.*` (separation of duties).

### 8. `RoleDataAccess`: Guide 4.3

| Field          | SQL type            | C# type   | Rule                                                            |
| -------------- | ------------------- | --------- | --------------------------------------------------------------- |
| RoleId         | NVARCHAR(450) PK/FK | `string`  |                                                                 |
| DataViewName   | SYSNAME             | `string?` | vw_Normal / vw_Accounting / vw_Privileged / null (UserAdmin)    |
| ConnectionName | VARCHAR(50)         | `string?` | CustomerNormal / CustomerAccounting / CustomerPrivileged / null |

### 9. `Session`: Guide 2.4

| Field             | SQL type           | C# type     | Req | Rule                                                                   |
| ----------------- | ------------------ | ----------- | --- | ---------------------------------------------------------------------- |
| SessionId         | BIGINT IDENTITY PK | `long`      | ✔   |                                                                        |
| UserId            | NVARCHAR(450) FK   | `string`    | ✔   |                                                                        |
| TokenHash         | BINARY(32) unique  | `byte[]`    | ✔   | SHA-256 of the 256-bit random token (the token itself is never stored) |
| CreatedUtc        | DATETIME2          | `DateTime`  | ✔   |                                                                        |
| LastSeenUtc       | DATETIME2          | `DateTime`  | ✔   | idle timeout 15 min                                                    |
| AbsoluteExpiryUtc | DATETIME2          | `DateTime`  | ✔   | Created + 8 h max                                                      |
| RevokedUtc        | DATETIME2          | `DateTime?` |     | set on logout, disable or role change                                  |

### 10. `AuditLog` (append-only): Guide 5

| Field            | SQL type           | C# type                               | Req | Rule                                                                                                                                                                                       |
| ---------------- | ------------------ | ------------------------------------- | --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| AuditId          | BIGINT IDENTITY PK | `long`                                | ✔   |                                                                                                                                                                                            |
| OccurredUtc      | DATETIME2(3)       | `DateTime`                            | ✔   |                                                                                                                                                                                            |
| ActorUserId      | NVARCHAR(450)      | `string?`                             |     | null for an unknown-user login fail                                                                                                                                                        |
| Action           | VARCHAR(30)        | `AuditAction` enum (stored as string) | ✔   | LoginSucceeded, LoginFailed, AccountLocked, MfaFailed, Logout, CardRevealed, MedicalViewed, AccessDenied, UserCreated, UserDisabled, RoleAssigned, PasswordReset, MfaReset, SearchUnlocked |
| Outcome          | VARCHAR(10)        | enum                                  | ✔   | Success / Denied / Failure                                                                                                                                                                 |
| TargetUserId     | NVARCHAR(450)      | `string?`                             |     |                                                                                                                                                                                            |
| TargetCustomerId | INT                | `int?`                                |     |                                                                                                                                                                                            |
| ApprovalRef      | NVARCHAR(50)       | `string?`                             |     | required when RoleAssigned succeeds                                                                                                                                                        |
| ClientIp         | VARCHAR(45)        | `string?`                             |     | IPv4/IPv6                                                                                                                                                                                  |

Never log passwords, card numbers, medical status or search names.

### 11. `SearchLog` (append-only, no names): Guide 2.2, R4

| Field             | SQL type           | C# type    | Req | Rule                                                 |
| ----------------- | ------------------ | ---------- | --- | ---------------------------------------------------- |
| SearchId          | BIGINT IDENTITY PK | `long`     | ✔   |                                                      |
| UserId            | NVARCHAR(450)      | `string`   | ✔   |                                                      |
| OccurredUtc       | DATETIME2(3)       | `DateTime` | ✔   |                                                      |
| UsedWildcard      | BIT                | `bool`     | ✔   |                                                      |
| PrefixLength      | TINYINT            | `byte`     | ✔   |                                                      |
| PrefixFingerprint | BINARY(32)         | `byte[]?`  |     | HMAC-SHA-256 of the prefix (alphabet-walk detection) |
| ResultCount       | SMALLINT           | `short`    | ✔   | 0–50                                                 |

Daily counts come from this table: 300 searches, 2,000 records; soft alert at 50%, hard stop at 100%.

### 12. `SecurityAlert`: Guide 2.2, 4.4

| Field            | SQL type           | C# type     | Req | Rule                                                                                                                 |
| ---------------- | ------------------ | ----------- | --- | -------------------------------------------------------------------------------------------------------------------- |
| AlertId          | BIGINT IDENTITY PK | `long`      | ✔   |                                                                                                                      |
| RaisedUtc        | DATETIME2          | `DateTime`  | ✔   |                                                                                                                      |
| UserId           | NVARCHAR(450)      | `string`    | ✔   |                                                                                                                      |
| AlertType        | VARCHAR(30)        | enum        | ✔   | SearchSoftLimit, SearchHardLimit, AlphabetWalk, CardRevealLimit, AccountLocked, RoleAssigned, PrivilegedRoleAssigned |
| ResolvedByUserId | NVARCHAR(450)      | `string?`   |     |                                                                                                                      |
| ResolvedUtc      | DATETIME2          | `DateTime?` |     | set together with ResolvedByUserId                                                                                   |

---

## Relationships

```
Locality 1 ── * Customer
ApplicationUser 1 ── 1 AspNetUserRoles ── 1 IdentityRole        (one role per user)
IdentityRole 1 ── * RolePermission * ── 1 Permission
IdentityRole 1 ── 1 RoleDataAccess
ApplicationUser 1 ── * Session
ApplicationUser 1 ── * AuditLog / SearchLog / SecurityAlert     (no FK: logs outlive users)
```

## Suggested model files

```
Models/Customer/Locality.cs, Customer.cs, MedicalStatus.cs
Models/Customer/Views/NormalCustomerView.cs, AccountingCustomerView.cs, PrivilegedCustomerView.cs
Models/Auth/ApplicationUser.cs, Permission.cs, RolePermission.cs, RoleDataAccess.cs,
            Session.cs, AuditLog.cs, SearchLog.cs, SecurityAlert.cs, Enums.cs
Data/CustomerDbContext.cs, AuthDbContext.cs (IdentityDbContext<ApplicationUser>)
```
