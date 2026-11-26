# SBD403 Assessment 3: secure customer search API

Source code for the Security Design Guide. An ASP.NET Core Web API (.NET 8) that lets staff search customer records, with the guide's security controls built in and tested. The values come from `project/SECURITY_SPEC.md`. Every security block in the code has a short comment: the guide section, why, the standard, and the test that proves it.

Report screenshots use a minimal demo front end; the production Next.js design is not built and the demo is not part of this submission. In production the Next.js server holds the session token in an HttpOnly cookie, so the browser never sees the token or the API key (a deployment item); `requests.http` shows the same flow against the API directly.

## Prerequisites

.NET 8 SDK, Docker (SQL Server 2022), `sqlcmd`, `openssl`.

## Setup

1. `cp .env.example .env`, then fill every value. Use long random values; generate keys with `openssl rand -base64 32` (the encryption key and the search fingerprint key must differ). `.env` is never committed or zipped.
2. Start SQL Server, bound to this machine only (§1.3):
   `docker run -d --name sql_server_container -e ACCEPT_EULA=Y -e MSSQL_SA_PASSWORD="$MSSQL_SA_PASSWORD" -p 127.0.0.1:1433:1433 mcr.microsoft.com/mssql/server:2022-latest`
3. Create the databases: follow the run order in `database/README.md` (schema, views, logins, `verify_rbac.sql`).
4. Load demo data: `dotnet run --project SBD.API -- seed` (4 demo users, 30 synthetic customers).
5. Run the API. It serves TLS 1.3 only, which macOS .NET cannot do, so on a Mac run it in a Linux container: `scripts/run_api_linux.sh` (makes a demo ECDSA P-384 certificate with `scripts/dev_cert.sh`, serves https://localhost:7443). On Linux or Windows: `dotnet run --project SBD.API --launch-profile https`.

Demo accounts (passwords come from your `.env`): `normal.user`, `accounting.user`, `privileged.user`, `user.admin`. The last three must enrol an authenticator app at first login. `requests.http` is the manual walkthrough.

## Tests and release checks

- `dotnet test`: runs against the real SQL Server (163 tests). Run the seed first on a fresh database.
- `scripts/release_check.sh`: build with warnings as errors, tests, vulnerable packages, raw SQL search, secrets search. Any failure stops the release.
- `scripts/build_zip.sh`: builds the submission ZIP and fails if a `.env` file is inside.

## Control → file → test

Paths are under `SBD.API/` (tests in `SBD.API.Tests/`).

| ID      | Control (Guide §)                                                                                 | File                                                                                 | Test                                                                                                                                                       |
| ------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V1      | Parameterised queries only (3.2)                                                                  | `Services/Customers/CustomerSearchService.cs`                                        | `Injection_InLastName_Rejected`, `Injection_AtQueryLayer_ReturnsNoRows`                                                                                    |
| V2, V3  | Field allowlists, trim + NFC, reject not clean (2.1)                                              | `Services/Customers/Functions/SearchRequestValidator.cs`, `InputNormaliser.cs`       | `Name_DisallowedChars_Rejected`, `Normalisation_NFC_FindsAccentedName`                                                                                     |
| V4, V5  | Wildcard rule, name or phone required (2.2)                                                       | `SearchRequestValidator.cs`                                                          | `Wildcard_Rules_Enforced`, `AddressOnlySearch_Rejected`                                                                                                    |
| V6      | Locality must match the list (2.1)                                                                | `Services/Customers/CustomerSearchService.cs`, `Services/Localities/`                | `InvalidLocality_Rejected`                                                                                                                                 |
| V7      | Phone length per country (2.1)                                                                    | `Services/Customers/Functions/PhoneLengthTable.cs`                                   | `Phone_WrongLengthForCountry_Rejected`                                                                                                                     |
| V9      | Generic errors (3.2)                                                                              | `Middleware/GlobalExceptionHandler.cs`                                               | `DbError_ReturnsGenericMessage`                                                                                                                            |
| E1, E2  | AES-256-GCM, nonce, tag, row-bound (3.3)                                                          | `Services/Encryption/FieldEncryptionService.cs`                                      | `Encrypt_Decrypt_RoundTrip`, `Tampered_Fails`, `CopiedToOtherRow_Fails`                                                                                    |
| E3      | 50-row cap, rate limit, daily quotas (2.2)                                                        | `Services/Customers/SearchQuotaService.cs`, `SetUp/RateLimitSetup.cs`                | `ResultCap_50`, `SearchRateLimit_31st_429`, `DailyHardLimit_Pauses`                                                                                        |
| E4, E5  | Alphabet-walk alert, HMAC fingerprint (§6)                                                        | `SearchQuotaService.cs`, `Services/Customers/Functions/SearchFingerprint.cs`         | `AlphabetWalk_RaisesAlert`, `SearchLog_ContainsNoNames`                                                                                                    |
| E6      | API key + IP allowlist (2.3)                                                                      | `Middleware/ApiKeyMiddleware.cs`, `IpAllowlistMiddleware.cs`                         | `WrongApiKey_401`, `NotAllowlistedIp_403`                                                                                                                  |
| E7, E8  | TLS 1.3, HTTPS, HSTS, headers, POST search (2.3)                                                  | `Program.cs`, `Middleware/SecurityHeadersMiddleware.cs`                              | `Hsts_HeaderPresent`, `SecurityHeaders_Present`, `Search_OverGet_NotAllowed`                                                                               |
| E9      | Secrets only in `.env` (3.2)                                                                      | `SetUp/EnvLoader.cs`, `scripts/release_check.sh`                                     | release check step 5                                                                                                                                       |
| E10     | 90-day inactive disable (4.2)                                                                     | `Services/Admin/InactiveAccountService.cs`, `InactiveAccountJob.cs`                  | `InactiveAccount_Disabled`                                                                                                                                 |
| A1, A2  | PBKDF2-SHA512, 600,000 iterations (2.4)                                                           | `Contexts/ServiceExtension.cs`                                                       | `Hasher_Uses600kIterations`, `Password_IsStoredAsHash_NotPlainText`                                                                                        |
| A3, A4  | Password length, no composition rules, breached list (2.4)                                        | `Services/Auth/Functions/PasswordPolicyValidator.cs`, `BreachedPasswordValidator.cs` | `Password_15Chars_Accepted`, `BreachedPassword_Rejected`                                                                                                   |
| A5      | Generic login error, similar timing (2.5)                                                         | `Services/Auth/AuthService.cs`, `Functions/DummyPasswordHash.cs`                     | `WrongUser_And_WrongPassword_SameResponse`                                                                                                                 |
| A6, A7  | Lockout 5 / 15 min, 10 logins per minute per IP (2.5)                                             | `AuthService.cs`, `SetUp/RateLimitSetup.cs`                                          | `SixthAttempt_AccountLocked`, `LoginRateLimit_11thRequest_429`                                                                                             |
| A8      | TOTP MFA for Accounting, Privileged, UserAdmin (2.4)                                              | `AuthService.cs`                                                                     | `Accounting_RequiresMfa`, `Normal_NoMfaRequired`                                                                                                           |
| A8b     | Turnstile after 3 failures, fail-safe (2.5)                                                       | `Services/Captcha/`                                                                  | `Captcha_RequiredAfter3Failures`, `Captcha_VerifierDown_LoginRefused`                                                                                      |
| A9, A10 | 256-bit session token, hash stored, 15 min idle, 8 h absolute, logout (2.4)                       | `Services/Session/`                                                                  | `SessionToken_StoredAsHash`, `IdleTimeout_Rejected`, `AbsoluteTimeout_Rejected`, `LoggedOutToken_Rejected`                                                 |
| R1      | One DTO per role (4.3)                                                                            | `Services/Customers/Dtos/CustomerDtos.cs`, `Models/Customer/Views/`                  | `Normal_SeesNoCardOrMedical`, `Privileged_SeesAllFields`                                                                                                   |
| R2      | Role read from AuthDb on every request (4.2)                                                      | `Services/Session/SessionAuthenticationHandler.cs`                                   | `ForgedRole_Ignored`, `RoleChange_TakesEffectOnNextRequest`                                                                                                |
| R3      | Deny by default, every route tested for every role (4.3)                                          | `Program.cs`, `Contexts/ServiceExtension.cs`                                         | `EveryEndpoint_HasPermissionPolicy`, `RouteMatrix_AllRolesAllEndpoints`                                                                                    |
| R4      | One read-only DB login per role view (3.2, 4.3)                                                   | `Contexts/CustomerViewContext.cs`, `database/03_customer_rbac.sql`                   | `ViewLogin_CannotOpenAuthDb`, `verify_rbac.sql`                                                                                                            |
| R5      | Card reveal: server check, audit, 20 per day (3.3, 4.4)                                           | `Services/Customers/CardRevealService.cs`                                            | `Reveal_Normal_Forbidden`, `Reveal_Accounting_Logged`, `Reveal_21st_Blocked`                                                                               |
| R6      | UserAdmin rules: no customer data, no self-change, approval ref, MFA, internal network (4.4, 2.6) | `Services/Admin/`                                                                    | `Admin_CannotSearch`, `Admin_CannotChangeOwnRole`, `RoleChange_NeedsApprovalRef`, `Admin_FromExternalIp_403`, `PasswordReset_ForcesChange_RevokesSessions` |
| R8      | Append-only audit log, no secrets in it (5)                                                       | `Services/Audit/AuditLogger.cs`, `database/10_auth_schema.sql`                       | `Login_WritesAuditRows`                                                                                                                                    |

## Deployment items (documented, not active in this demo)

- Next.js front end and the HttpOnly, Secure, SameSite session cookie (the demo returns a bearer token).
- TLS on the Next.js link and the database link, with CA-signed certificates (the demo uses the Docker self-signed certificate on localhost). Only the API's Kestrel port is verified as TLS 1.3 only, in a Linux container: macOS .NET cannot serve TLS 1.3.
- Key vault and key rotation for `FieldEncryption__Key`; encrypted backups.
- Quarterly manager re-confirmation of roles.
- The Turnstile secret in `.env.example` is Cloudflare's public test key; production needs a real site key.
