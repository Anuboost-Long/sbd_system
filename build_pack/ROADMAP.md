# Build Roadmap: Secure Customer Search API

**Read this whole file before writing code. Build the phases in order. Finish each phase's "Done when" check before starting the next.**

## What we are building

A small ASP.NET Core Web API that lets staff log in and search customer records.
It is the code that goes with a university security design guide (SBD403 Assessment 3).
The marker checks that **each security control is really implemented, tested and commented**.
There is **no front end**. The API is used through tests and `requests.http`.

- Stack: ASP.NET Core Web API (use the .NET version already in the project), EF Core (SQL Server provider),
  ASP.NET Core Identity, xUnit, SQL Server 2022 in Docker.
- The project, Docker and SQL Server are **already set up**. Look at the existing solution first and fit into it.
  Do not recreate the project.
- The database is **already designed** in `database/*.sql`. The API maps to it.
  **Never run EF migrations** against these databases.
- Field types for the models: `db_model_spec.md`.

---

## Rules for the whole build

### R1. Comment every security control like this

```csharp
// [Guide §2.5] Lock the account for 15 minutes after 5 failed logins.
// Why: slows password guessing; lockout is the main control because bots can solve CAPTCHAs.
// Standard: OWASP ASVS 5.0 V6.3.1; NIST SP 800-63B-4.
// Test: SixthAttempt_AccountLocked
```

- Every step below marked 🔒 gets one of these blocks. The `[Guide §x]`, `Standard:` and `Test:` lines are given in the step.
- Plain English; put the technical term in brackets: "random value per entry (nonce)".
- Say **what** and **why**, not how C# works. 4–6 lines max.
- Every security file starts with a header:
  ```csharp
  /*
   * Implements: Guide §2.4 password rules (min 15, or 8 with MFA; max 128; no composition rules; breached list).
   */
  ```
- **Only use the standard IDs written in this roadmap.** Never invent requirement numbers.
- If something is production-only, comment it as `// [Guide §x] DEPLOYMENT ITEM, not active in this demo: ...`
- Never mention AI or this roadmap in code comments.

### R2. Security rules (never break)

- **No raw SQL built from strings.** No `FromSqlRaw`, `ExecuteSqlRaw` or `SqlCommand` with concatenated input. LINQ only.
- **No secrets** in code, `appsettings*.json`, tests or comments. Everything comes from environment variables / `.env`.
- **Synthetic data only.** Test card numbers only (e.g. `4111111111111111`).
- **Never log** passwords, session tokens, card numbers, expiry, medical status or typed search names.
- Errors to the client are generic. No stack traces, no SQL.
- Do not change any number in this roadmap (limits, lengths, timeouts). If one can't be built, write it in `MISMATCHES.md` and tell the user.

### R3. Tests

- Test names are given in each step. Use them exactly.
- Never weaken a test to make it pass. Report real results only.

---

## Phase 0: Check the setup

- [ ] Read the existing solution structure, `docker-compose.yml`, `.env`, `.gitignore`.
- [ ] Make sure `.gitignore` contains `.env`, `.env.*` (except `.env.example`), `bin/`, `obj/`.
- [ ] Create or update `.env.example` with these names and **empty values**:
  ```
  MSSQL_SA_PASSWORD=
  APP_VIEW_NORMAL_PASSWORD=
  APP_VIEW_ACCOUNTING_PASSWORD=
  APP_VIEW_PRIVILEGED_PASSWORD=
  APP_SEED_PASSWORD=
  APP_IDENTITY_PASSWORD=
  ConnectionStrings__Auth=
  ConnectionStrings__CustomerNormal=
  ConnectionStrings__CustomerAccounting=
  ConnectionStrings__CustomerPrivileged=
  ConnectionStrings__CustomerSeed=
  FieldEncryption__Key=            # 32 random bytes, Base64
  SearchFingerprint__Key=          # 32 random bytes, Base64 (different from above)
  Security__ApiKey=                # 32 random bytes, Base64
  Security__AllowedIps=127.0.0.1,::1
  Security__AdminAllowedIps=127.0.0.1,::1
  Turnstile__SecretKey=            # Cloudflare test secret: 1x0000000000000000000000000000000AA
  SEED_NORMAL_PASSWORD=
  SEED_ACCOUNTING_PASSWORD=
  SEED_PRIVILEGED_PASSWORD=
  SEED_USERADMIN_PASSWORD=
  ```
- [ ] 🔒 `Config/EnvLoader.cs`: a small in-house `.env` reader (no NuGet package). Reads `KEY=VALUE` lines, skips `#` comments,
      **never overrides a variable that is already set**. Called first in `Program.cs`.
      Comment: `[Guide §3.2]` secrets live outside the code and outside the ZIP. Why: leaked secrets risk R7; in-house loader avoids a dependency. Standard: OWASP Secrets Management Cheat Sheet.
- [ ] Connection strings use the matching SQL login (`app_identity`, `app_view_normal`, …), `Encrypt=True;TrustServerCertificate=True` for local Docker.
      🔒 Comment on the connection setup: `[Guide §2.3, §3.2] DEPLOYMENT ITEM`: production uses a CA-signed certificate with TLS 1.3 enforced on SQL Server; demo trusts the Docker self-signed certificate on localhost only.

**Done when:** API starts, reads all values from `.env`, `git status` shows no `.env` file.

---

## Phase 1: Database and models

- [ ] Run the scripts in `database/README.md` order on the local SQL Server, then `verify_rbac.sql`. All lines must say PASS.
- [ ] In the existing `database/*.sql` comments change `[Guide x.y]` to `[Guide §x.y]`. Do not change SQL logic.
- [ ] Create models from `db_model_spec.md`:
  - `Models/Customer/`: `Locality`, `Customer`, `MedicalStatus` enum (1 Sick, 2 Healthy, 3 Cancer, 4 Deceased, 5 Flu, 6 Covid),
    and keyless view models `NormalCustomerRow`, `AccountingCustomerRow`, `PrivilegedCustomerRow`.
  - `Models/Auth/`: `ApplicationUser : IdentityUser` (+ `IsDisabled`, `LastLoginUtc`, `SearchPausedUntilUtc`, `CreatedUtc`),
    `Permission`, `RolePermission`, `RoleDataAccess`, `Session`, `AuditLog`, `SearchLog`, `SecurityAlert`, enums for Action/Outcome/AlertType (stored as strings).
- [ ] DbContexts:
  - `AuthDbContext : IdentityDbContext<ApplicationUser>`, connection `Auth`.
  - 🔒 `NormalViewContext`, `AccountingViewContext`, `PrivilegedViewContext`: each maps **only its own view** (`HasNoKey().ToView("vw_Normal")` etc.) and uses **its own login**.
    Comment: `[Guide §3.2, §4.3]` each role reads through a database login that can only see its own view, so a coding mistake cannot reach other columns. Why: defence in depth (rights enforced twice). Standard: OWASP ASVS 5.0 V8.2.3; Sandhu et al. (1996). Test: DB1–DB4 in `verify_rbac.sql`.
  - `SeedContext`: maps `Customers` + `Localities` tables, connection `CustomerSeed` (used only by the seed command).
  - Turn EF sensitive-data logging **off**.

**Done when:** the API builds and a quick query through each context works.

---

## Phase 2: API foundation

Put these in `Security/` and wire them in `Program.cs` in this order:
`HTTPS redirect → HSTS → security headers → IP allowlist → API key → exception handler → rate limiter → authentication → authorization → endpoints`.

- [ ] 🔒 **HTTPS + TLS 1.3 only.** Kestrel `ConfigureHttpsDefaults(o => o.SslProtocols = SslProtocols.Tls13)`, `UseHttpsRedirection()`, `UseHsts()`.
      Comment: `[Guide §2.3]` TLS 1.3 only. Why: removes older protocol weaknesses; above the NIST TLS 1.2 baseline. Standard: ASD ISM-1139, ISM-1369, ISM-1372; NIST SP 800-52 Rev. 2. Test: manual `openssl s_client -tls1_2` refused.
      ⚠️ On macOS, .NET may not support a TLS 1.3-only server. If it fails, run the API in a Linux Docker container for this check, or record it in `MISMATCHES.md`.
- [ ] 🔒 `SecurityHeadersMiddleware`: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
      Guide §2.3, §2.2 · Standard: OWASP HTTP Headers Cheat Sheet · Test: `SecurityHeaders_Present`
- [ ] 🔒 `IpAllowlistMiddleware`: uses `HttpContext.Connection.RemoteIpAddress` only (never `Host` or `X-Forwarded-For`); compares against `Security__AllowedIps`; otherwise 403.
      Guide §2.3: only the Next.js server may call the API · Why: small attack surface; an address proves origin, not identity, so the API key is also needed · Test: `NotAllowlistedIp_403`
      (TestServer has no remote IP: in tests, add a startup filter that sets it to 127.0.0.1, plus one test that sets a different IP.)
- [ ] 🔒 `ApiKeyMiddleware`: header `X-Api-Key`, compare with `CryptographicOperations.FixedTimeEquals`; otherwise 401.
      Guide §2.3 · Why: proves the caller is our server; constant-time compare avoids timing leaks · Test: `MissingApiKey_401`, `WrongApiKey_401`
- [ ] 🔒 Global exception handler: returns `ProblemDetails` with a generic message and a correlation ID; logs details server-side.
      Guide §3.2, §5 · Standard: OWASP Error Handling Cheat Sheet · Test: `DbError_ReturnsGenericMessage`
- [ ] 🔒 **Deny by default:** `FallbackPolicy = RequireAuthenticatedUser`, and every endpoint must have an explicit permission policy (Phase 3) or `[AllowAnonymous]` (login endpoints only).
      Guide §4.3, §5 fail-safe defaults · Standard: OWASP ASVS 5.0 V8.2.1 · Test: `EveryEndpoint_HasPermissionPolicy` (enumerate `EndpointDataSource`, fail if any endpoint has neither).
- [ ] 🔒 Rate limiter (built-in `Microsoft.AspNetCore.RateLimiting`):
  - policy `login`: fixed window **10 per minute per IP** → 429. Guide §2.5 · Standard: OWASP ASVS 5.0 V6.3.1 · Test: `LoginRateLimit_11thRequest_429`
  - policy `search`: fixed window **30 per minute per user ID** → 429. Guide §2.2 (risk R4) · Test: `SearchRateLimit_31st_429`
- [ ] 🔒 `Audit/AuditLogger`: writes `AuditLog` rows. Method signature accepts only IDs, action, outcome, approval ref and IP; **no free-text fields**, so secrets can't be logged.
      Guide §5 · Standard: OWASP ASVS 5.0 V16; OWASP Logging Cheat Sheet

**Done when:** all Phase 2 tests pass.

---

## Phase 3: Authentication

Use `AddIdentityCore<ApplicationUser>().AddRoles<IdentityRole>().AddEntityFrameworkStores<AuthDbContext>().AddSignInManager().AddDefaultTokenProviders()`.
Do **not** use Identity cookies. We issue our own session token.

- [ ] 🔒 **Password hashing:** `PasswordHasherOptions.IterationCount = 600_000` (Identity v3 format = PBKDF2-HMAC-SHA512, salted).
      Guide §2.4 · Why: slow salted hash; PBKDF2 chosen over Argon2id to avoid an extra dependency · Standard: OWASP ASVS 5.0 V11.4.2; OWASP Password Storage Cheat Sheet · Test: `Password_IsStoredAsHash_NotPlainText`, `Hasher_Uses600kIterations` (decode the hash: byte 0 = 0x01, iteration count = 600000)
- [ ] 🔒 **Password rules:** Identity options: `RequireDigit/Lowercase/Uppercase/NonAlphanumeric = false`, `RequiredUniqueChars = 1`, `RequiredLength = 8`.
      Custom `PasswordPolicyValidator : IPasswordValidator`: minimum **15**, or **8** if the user's role requires MFA (Accounting, Privileged, UserAdmin); maximum **128** (accepts at least 64).
      Guide §2.4 · Why: length beats complexity rules (Shay et al., 2016) · Standard: OWASP ASVS 5.0 V6.2.1, V6.2.5, V6.2.9; NIST SP 800-63B-4 · Tests: `Password_14Chars_Rejected`, `Password_15Chars_Accepted`, `Password_64Chars_Accepted`, `Password_NoCompositionRules`
- [ ] 🔒 **Breached passwords:** `BreachedPasswordValidator` checks against `Data/breached-passwords.txt` (a common-passwords list, e.g. from SecLists, MIT licence; include ≥10,000 entries; case-insensitive `HashSet`).
      Guide §2.4 · Standard: OWASP ASVS 5.0 V6.2.12 · Test: `BreachedPassword_Rejected`
- [ ] 🔒 **Lockout:** `MaxFailedAccessAttempts = 5`, `DefaultLockoutTimeSpan = 15 min`, `AllowedForNewUsers = true`. Use `CheckPasswordSignInAsync(user, pw, lockoutOnFailure: true)`.
      Guide §2.5 · Standard: OWASP ASVS 5.0 V6.3.1, V6.1.1; NIST SP 800-63B-4 · Test: `SixthAttempt_AccountLocked` (6th attempt fails even with the correct password)
- [ ] 🔒 **Generic failure + similar timing:** unknown user, wrong password, locked, disabled → same status (401), same body `{"error":"Invalid username or password."}`. For an unknown user still run `VerifyHashedPassword` against a dummy hash.
      Guide §2.5 · Standard: OWASP ASVS 5.0 V6.3.8 · Test: `WrongUser_And_WrongPassword_SameResponse`
- [ ] 🔒 **CAPTCHA (Turnstile) after 3 failures:** keep a failure count per username (memory cache, 15 min) so unknown users behave the same. From the 4th attempt the request must include `captchaToken`.
      `TurnstileVerifier` (interface `ICaptchaVerifier`) POSTs to `https://challenges.cloudflare.com/turnstile/v0/siteverify`. **If the call fails or times out → login refused.**
      Guide §2.5 · Why: fail-safe default; lockout stays primary because bots solve CAPTCHAs (Searles et al., 2023) · Tests (mock the verifier): `Captcha_RequiredAfter3Failures`, `Captcha_VerifierDown_LoginRefused`
- [ ] 🔒 **MFA (TOTP)** for roles Accounting, Privileged, UserAdmin:
  - `POST /auth/login {username, password, captchaToken?}`:
    - Normal role → session.
    - MFA role → `{ mfaRequired: true, mfaTicket }` (ticket: random 32 bytes, memory cache, 5 min, single use).
    - MFA role but not enrolled → `{ mfaSetupRequired: true, mfaTicket }`.
  - `POST /auth/mfa/setup {mfaTicket}` → returns the **manual setup key** (`GetAuthenticatorKeyAsync`; reset if empty). No QR library.
  - `POST /auth/mfa/confirm {mfaTicket, code}` → enables 2FA and issues the session.
  - `POST /auth/mfa {mfaTicket, code}` → `VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultAuthenticatorProvider, code)`.
  - A wrong code calls `AccessFailedAsync`, so it **counts toward lockout**.
    Guide §2.4 · Why: every account that can see card, medical or role data needs MFA (Medibank breach lesson, Guide §6) · Standard: OWASP ASVS 5.0 V6.3.3 · Tests: `Accounting_RequiresMfa`, `Normal_NoMfaRequired`, `WrongMfaCode_CountsTowardLockout`
    (Tests need a small TOTP generator, RFC 6238 with HMAC-SHA1, 6 digits and a 30 s step, in the test project.)
- [ ] 🔒 **Session token:** `RandomNumberGenerator.GetBytes(32)` (256-bit) → returned once as Base64Url; store only `SHA256.HashData(token)` in `Sessions.TokenHash`.
      `AbsoluteExpiryUtc = now + 8 h`.
      Guide §2.4 · Why: a stolen AuthDb can't be used to hijack sessions · Standard: OWASP ASVS 5.0 V11.5.1; OWASP Session Management Cheat Sheet · Test: `SessionToken_StoredAsHash`
      Comment `DEPLOYMENT ITEM`: in production Next.js keeps this token server-side and gives the browser an HttpOnly, Secure, SameSite cookie. The demo returns it as a bearer token.
- [ ] 🔒 **`SessionAuthenticationHandler`** (custom scheme, `Authorization: Bearer <token>`), on **every request**:
  1. hash the token → find the session; reject if revoked, older than 8 h, or idle > **15 min** (`LastSeenUtc`);
  2. reject if the user is disabled or locked;
  3. **load the user's role and permissions from AuthDb** (`AspNetUserRoles` → `RolePermissions` → `Permissions`) and `RoleDataAccess`;
  4. build the `ClaimsPrincipal` with claims `perm:<code>` and `role`; update `LastSeenUtc`.
     Guide §4.2, §4.4 · Why: the role is never taken from the client, so it can't be forged · Standard: OWASP ASVS 5.0 V8.3.1 · Tests: `ForgedRole_Ignored` (send role in header, body and query), `IdleTimeout_Rejected`, `AbsoluteTimeout_Rejected`, `DisabledUser_SessionRejected`
- [ ] 🔒 **Permission policies:** one policy per permission code (`RequireClaim("perm", code)`). Endpoints use `.RequireAuthorization("customer.search")` etc.
      Guide §4.1, §4.3 · Standard: OWASP ASVS 5.0 V8.2.1
- [ ] 🔒 `POST /auth/logout`: sets `RevokedUtc`. Guide §2.4 · Test: `LoggedOutToken_Rejected`
- [ ] On successful login: set `LastLoginUtc`, audit `LoginSucceeded`. On failure: audit `LoginFailed` (user ID if known, never the password). On lockout: audit `AccountLocked` + `SecurityAlert AccountLocked`.
- [ ] **Seed users** (seed command, Phase 4): one per role (`normal.user`, `accounting.user`, `privileged.user`, `user.admin`), passwords from `SEED_*_PASSWORD`.

**Done when:** all Phase 3 tests pass.

---

## Phase 4: Search, encryption and card reveal

### 4a. Encryption

- [ ] 🔒 `Security/FieldEncryptionService`:
  - `AesGcm` with a 256-bit key from `FieldEncryption__Key`;
  - random **12-byte nonce** per value and a **16-byte tag**;
  - associated data = UTF-8 of `"{customerId}:{columnName}"`;
  - output `"v1:" + Base64(nonce ‖ ciphertext ‖ tag)`;
  - decrypt rejects an unknown version, a bad tag, or the wrong row/column.
    Guide §3.3 · Why: database staff and stolen backups see only ciphertext; the tag detects tampering; binding to the row stops values being copied to another customer · Standard: OWASP ASVS 5.0 V11.3.2, V11.3.3, V11.3.4; ASD ISM (Sep 2026); PCI DSS v4.0.1 Req 3.5.1 · Tests: `Encrypt_Decrypt_RoundTrip`, `SameValue_DifferentCiphertext`, `Tampered_Fails`, `CopiedToOtherRow_Fails`
    Comment `DEPLOYMENT ITEM`: production key in a vault with rotation; `v1:` prefix allows a new key version.
- [ ] 🔒 Medical status is stored as a one-digit code (1–6), so every ciphertext has the same length. Guide §3.1 (equal length hides the status).
- [ ] 🔒 `Security/CardNumber`: digits only, **10–19 digits**, **Luhn check**, pad to 19 with `#` before encrypting (strip on decrypt), keep the last 4 as `CardLast4`; expiry `MM/YY` with month 01–12.
      Guide §3.1, §3.3 · Standard: ISO/IEC 7812-1:2017; PCI DSS v4.0.1 Req 3.4.1 (masking) · Tests: `Card_LuhnInvalid_Rejected`, `Card_Length9_Rejected`, `Card_Length20_Rejected`

### 4b. Seed command

- [ ] `dotnet run -- seed`: creates the 4 users + ~30 synthetic customers (real localities from `04_seed_localities.sql`, test card numbers, random medical codes), using the `CustomerSeed` connection.
      Because the row ID is part of the encryption, insert each row with placeholders `v0:pending`, read the new `CustomerId`, then update with the real ciphertext, **in one transaction**.

### 4c. Input validation

- [ ] 🔒 `Search/InputNormaliser`: `Trim()` then `Normalize(NormalizationForm.FormC)` on every text field **before** validation.
      Guide §2.1 · Why: one canonical form so look-alike characters can't slip past checks · Standard: OWASP Input Validation Cheat Sheet
- [ ] 🔒 `Search/SearchRequestValidator`: reject (400 + field error), never "clean up". Rules after normalising:

| Field                                    | Rule (regex)                                                                                             |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| FirstName, LastName (optional in search) | `^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,49}$`, or the same plus one trailing `*` (see wildcard)                 |
| Unit (optional)                          | `^[A-Za-z0-9/\-]{1,10}$`                                                                                 |
| Street (optional)                        | `^[\p{L}\p{M}0-9][\p{L}\p{M}0-9 '\-.]{0,59}$`                                                            |
| State (optional)                         | one of `NSW VIC QLD SA WA TAS NT ACT`                                                                    |
| Suburb + Postcode (optional)             | Postcode `^\d{4}$`; if any of state/suburb/postcode is given, the combination must exist in `Localities` |
| Phone (optional)                         | `^\+\d{7,15}$`, or prefix + `*`; national length must match the country table                            |

Guide §2.1, §2.2 · Why: server-side allowlist; browser checks are only for usability · Standard: OWASP ASVS 5.0 V2; OWASP Input Validation Cheat Sheet · Tests: `LastName_50Chars_Accepted`, `LastName_51Chars_Rejected`, `Name_DisallowedChars_Rejected` (`<script>`, `Smith;`, `1Smith`), `Name_Apostrophe_And_Accent_Accepted` (`O'Brien`, `Zoë`, `Mary-Jane`), `Postcode_NotFourDigits_Rejected`, `InvalidLocality_Rejected` (Richmond, QLD, 3121)

- [ ] 🔒 **Wildcard:** only first name, last name and phone; exactly one `*`, **at the end**, after **at least 3** characters.
      Guide §2.2 · Why: limits bulk harvesting (risk R4) · Tests: `Wildcard_Rules_Enforced` (`*`, `Sm*`, `S*m`, `**` rejected; `Smi*` accepted)
- [ ] 🔒 **Name or phone required:** at least one of FirstName, LastName, Phone. Guide §2.2 · Test: `AddressOnlySearch_Rejected`
- [ ] 🔒 `Search/PhoneLengthTable`: in-house dictionary of country code → allowed national lengths (at least +61 → 9, +64 → 8–10, +1 → 10, +44 → 9–10, +65 → 8, +91 → 10; longest prefix match).
      Guide §2.1 · Why: no third-party phone library, which reduces supply-chain exposure at the cost of maintenance · Standard: ITU-T E.164 · Test: `Phone_WrongLengthForCountry_Rejected`
- [ ] Search uses **POST** `/customers/search` (personal data stays out of URLs, Guide §2.3).

### 4d. Query (the SQL injection defence)

- [ ] 🔒 `Search/CustomerSearchService`: pick the context from the user's `RoleDataAccess.ConnectionName` (unknown/none → 403). Build the query with LINQ only:
  - exact match: `row.LastName == lastName`;
  - wildcard: `EF.Functions.Like(row.LastName, Escape(prefix) + "%", "\\")`, where `Escape` puts `\` before `\`, `%`, `_` and `[`.
  - `.OrderBy(LastName).ThenBy(FirstName).Take(50)`.
    Comment on the query: `[Guide §3.2]` fixed command with the values sent separately (parameterised query), so input is always data, never a command. Escaping only stops `%` and `_` acting as wildcards; it is not the injection defence. · Standard: OWASP ASVS 5.0 V1.2.4; OWASP SQL Injection Prevention Cheat Sheet; Halfond et al. (2006) · Tests: `Injection_InLastName_Rejected` (`' OR '1'='1` → 400), `Injection_InPhone_Rejected`, `Injection_AtQueryLayer_ReturnsNoRows` (call the service directly, skipping the validator, with `' OR '1'='1` → 0 rows, not all rows)
- [ ] For evidence: in Development, `LogTo(Console.WriteLine, LogLevel.Information)` on the view contexts so the console shows `WHERE [v].[LastName] = @p0` (sensitive-data logging stays off).
- [ ] 🔒 **50-row cap, no paging:** request has no page/skip field; any `page`, `skip` or `offset` in the body → 400.
      Guide §2.2 · Tests: `ResultCap_50`, `Paging_Refused`

### 4e. Role-based results

- [ ] 🔒 DTOs: one per role, returned by the API.

| DTO                | Fields                                                                                  |
| ------------------ | --------------------------------------------------------------------------------------- |
| `NormalResult`     | Id, FirstName, LastName, Unit, Street, Suburb, State, Postcode, Phone                   |
| `AccountingResult` | Normal fields + `CardMasked` (`**** **** **** 1234`)                                    |
| `PrivilegedResult` | Accounting fields + `CardNumber`, `CardExpiry`, `MedicalStatus` (decrypted, label text) |

Guide §4.1, §4.3 · Why: the API sends only fields the role may see; the database view is the second barrier · Standard: OWASP ASVS 5.0 V8.2.3; Sandhu et al. (1996) · Tests: `Normal_SeesNoCardOrMedical`, `Accounting_SeesMaskedCard_NoMedical`, `Privileged_SeesAllFields` (check the raw JSON has no extra properties)

- [ ] Every Privileged result that includes medical status → audit `MedicalViewed` (one row per customer returned).

### 4f. Card reveal

- [ ] 🔒 `POST /customers/{id}/card/reveal`, permission `customer.card.reveal` (Accounting, Privileged). Decrypts and returns the full number + expiry; audit `CardRevealed` with the customer ID (**not** the number); **max 20 per user per day** (count today's `CardRevealed` rows) → 429 + `SecurityAlert CardRevealLimit`.
      Guide §3.3, §4.4 · Standard: OWASP ASVS 5.0 V8.2.1; PCI DSS v4.0.1 Req 3.4.1 · Tests: `Reveal_Normal_Forbidden`, `Reveal_Accounting_Logged`, `Reveal_21st_Blocked`

### 4g. Anti-harvesting (risk R4)

- [ ] 🔒 `Search/QuotaService`, checked before each search (counts today's rows from `SearchLog`, per user):

| Limit            | Daily | At 50%                             | At 100%                                                                   |
| ---------------- | ----- | ---------------------------------- | ------------------------------------------------------------------------- |
| Searches         | 300   | alert `SearchSoftLimit` (once/day) | set `SearchPausedUntilUtc` far ahead, alert `SearchHardLimit`, return 429 |
| Records returned | 2,000 | same                               | same                                                                      |

If `SearchPausedUntilUtc` > now → 429 until a UserAdmin unlocks.
Guide §2.2, §6 · Why: per-minute limits alone still allow 1,500 records a minute · Tests: `DailyHardLimit_Pauses`, `SoftLimit_RaisesAlert`, `Unlock_ResumesSearch`

- [ ] 🔒 `Security/SearchFingerprint`: `HMACSHA256(SearchFingerprint__Key, lowercase prefix)`. `SearchLog` stores the user, wildcard flag, prefix length, fingerprint and result count, **never the name**.
      Guide §5, §6 · Why: detects patterns without keeping personal data (Privacy Act) · Test: `SearchLog_ContainsNoNames`
- [ ] 🔒 **Alphabet-walk alert:** if a user makes **≥15 wildcard searches with different fingerprints within 10 minutes** → `SecurityAlert AlphabetWalk`.
      (The guide names the alert but not the threshold; this threshold is an implementation choice. Add it to `MISMATCHES.md` so the report can mention it.)
      Guide §6 · Test: `AlphabetWalk_RaisesAlert`

### 4h. Localities lookup

- [ ] `GET /localities?state=VIC` (permission `customer.search`) → suburbs + postcodes for dropdowns. Guide §2.1 (single list for UI, server and storage).

**Done when:** all Phase 4 tests pass and the console shows `@p0` parameters for the injection test.

---

## Phase 5: User Admin

All endpoints under `/admin`. Each needs its permission (UserAdmin only) **and** the caller's IP in `Security__AdminAllowedIps`.

- [ ] 🔒 Shared rules (one helper/filter, commented once):
  - the caller must have used MFA (the UserAdmin role always does, Phase 3);
  - the internal-network IP check;
  - **the target user ≠ the caller** (no self-change);
  - every action writes `AuditLog`.
    Guide §4.4 · Why: separation of duties; admins manage accounts but see no customer data · Standard: ISO/IEC 27001:2022; OWASP ASVS 5.0 V8.2.1 · Tests: `Admin_CannotChangeOwnRole`, `Admin_CannotSearch`, `Admin_FromExternalIp_403`, `NonAdmin_CannotCallAdmin`
- [ ] 🔒 `POST /admin/users` (`user.create`): username, role, temporary password, `approvalRef` (required). One role only.
- [ ] 🔒 `POST /admin/users/{id}/role` (`user.role.assign`): requires `approvalRef`. **Role change + audit row in one transaction** (the database CHECK rejects a `RoleAssigned` audit row without an approval ref, which rolls back the change). Revoke the user's sessions. Alert `RoleAssigned`, or `PrivilegedRoleAssigned` for Accounting/Privileged/UserAdmin.
      Guide §4.2, §4.4 · Test: `RoleChange_NeedsApprovalRef`, `RoleChange_RevokesSessions`
- [ ] 🔒 `POST /admin/users/{id}/disable` (`user.disable`): `IsDisabled = true`, revoke sessions. Guide §4.2 · Test: `DisabledUser_SessionRejected`
- [ ] 🔒 `POST /admin/users/{id}/password-reset` (`user.password.reset`): sets a temporary password, adds claim `must_change_password`, revokes sessions, audit. While that claim exists, the user can only call `POST /auth/change-password`.
      Guide §2.6 (resets by User Admin after an out-of-band identity check; no secret questions or email self-service) · Test: `PasswordReset_ForcesChange_RevokesSessions`
- [ ] 🔒 `POST /admin/users/{id}/mfa-reset` (`user.mfa.reset`): `ResetAuthenticatorKeyAsync`, disable 2FA (the next login forces re-enrolment), revoke sessions, audit. Guide §2.6
- [ ] 🔒 `POST /admin/users/{id}/search-unlock` (`user.search.unlock`): clears `SearchPausedUntilUtc`, resolves the alert, audit. Guide §2.2, §6
- [ ] 🔒 `Admin/InactiveAccountJob : BackgroundService`, daily: disable accounts with `LastLoginUtc` (or `CreatedUtc`) older than **90 days**. Put the logic in a method the test can call directly.
      Guide §4.2 · Test: `InactiveAccount_Disabled`

**Done when:** all Phase 5 tests pass.

---

## Phase 6: Tests and evidence

- [ ] Test project uses `WebApplicationFactory` against the Docker SQL Server. Each test creates its own users (unique names) so lockout state doesn't leak between tests.
- [ ] 🔒 **Route matrix** `RouteMatrix_AllRolesAllEndpoints`: every endpoint × {anonymous, Normal, Accounting, Privileged, UserAdmin} → expected status table. Guide §4.3 (every route tested for every role) · Standard: OWASP ASVS 5.0 V8.2.1
- [ ] Each test has a one-line comment: `// Guide §2.5 lockout`.
- [ ] `requests.http`: a manual demo of login → MFA → search as each role → injection attempt → reveal → admin actions (tokens as variables, no real secrets).
- [ ] Run `dotnet test --logger "console;verbosity=normal"` and save the output to `evidence/test-results.txt`.
- [ ] Save evidence (the user takes screenshots):
  - `verify_rbac.sql` output;
  - the injection request + 400 response + console `@p0` line;
  - three role responses side by side;
  - the DB view of `PasswordHash`, `Sessions.TokenHash` and the `v1:` ciphertext columns;
  - the lockout sequence;
  - `openssl s_client -connect localhost:<port> -tls1_2` refused and `-tls1_3` accepted.

---

## Phase 7: Release checks and packaging

- [ ] 🔒 `scripts/release_check.sh` (fails on any error):
  1. `dotnet build -warnaserror`
  2. `dotnet test`
  3. `dotnet list package --vulnerable --include-transitive` → fail if any found
  4. `grep -rnE "FromSqlRaw|ExecuteSqlRaw|SqlCommand" --include=*.cs` → fail if found
  5. secrets check: fail if `.env` is tracked or any `Password=`/key value appears in `*.cs`/`*.json`

  Guide §5 · Why: authorisation, injection and dependency checks block a release on failure (DevSecOps) · Standard: NIST SSDF (SP 800-218); OWASP SAMM

- [ ] `scripts/build_zip.sh` → `Ly_K_SBD403_A3_code.zip` of the whole project, **excluding** `.env`, `.env.*` (keep `.env.example`), `bin/`, `obj/`, `.vs/`, `.idea/`, `evidence/`, `ROADMAP.md`, `MISMATCHES.md`. After zipping, list the contents and fail if any `.env` file is inside.
- [ ] `README.md` (project root): what it is, prerequisites, setup (`.env` from `.env.example`, `docker compose up -d`, DB scripts, `dotnet run -- seed`, `dotnet run`), how to run tests, demo accounts (usernames only, passwords come from your `.env`), a table of **control → file → test**, and the list of deployment-only items.

**Done when:** `release_check.sh` passes and the ZIP contains no secrets.

---

## Allowed standard references (use only these)

| Topic                                  | Cite                                                                         |
| -------------------------------------- | ---------------------------------------------------------------------------- |
| Password length / no composition / max | OWASP ASVS 5.0 V6.2.1, V6.2.5, V6.2.9; NIST SP 800-63B-4                     |
| Breached passwords                     | OWASP ASVS 5.0 V6.2.12                                                       |
| Lockout                                | OWASP ASVS 5.0 V6.3.1, V6.1.1; NIST SP 800-63B-4                             |
| MFA                                    | OWASP ASVS 5.0 V6.3.3                                                        |
| Generic login errors                   | OWASP ASVS 5.0 V6.3.8                                                        |
| Password hashing                       | OWASP ASVS 5.0 V11.4.2; OWASP Password Storage Cheat Sheet                   |
| Session token                          | OWASP ASVS 5.0 V11.5.1; OWASP Session Management Cheat Sheet                 |
| Parameterised queries                  | OWASP ASVS 5.0 V1.2.4; OWASP SQL Injection Prevention Cheat Sheet            |
| Input validation                       | OWASP ASVS 5.0 V2; OWASP Input Validation Cheat Sheet                        |
| Access control / deny by default       | OWASP ASVS 5.0 V8.2.1                                                        |
| Field-level access                     | OWASP ASVS 5.0 V8.2.3                                                        |
| Server-side role                       | OWASP ASVS 5.0 V8.3.1                                                        |
| Encryption                             | OWASP ASVS 5.0 V11.3.2, V11.3.3, V11.3.4; ASD ISM (Sep 2026)                 |
| Card data                              | PCI DSS v4.0.1 Req 3.4.1, Req 3.5.1                                          |
| TLS                                    | ASD ISM-1139, ISM-1369, ISM-1372; NIST SP 800-52 Rev. 2                      |
| Headers / errors / logging             | OWASP HTTP Headers, Error Handling, Logging Cheat Sheets; OWASP ASVS 5.0 V16 |
| Separation of duties                   | ISO/IEC 27001:2022                                                           |
| Phone                                  | ITU-T E.164                                                                  |
| Card number                            | ISO/IEC 7812-1:2017                                                          |
| Secure development                     | NIST SSDF (SP 800-218); OWASP SAMM                                           |
| Design principles                      | Saltzer & Schroeder (1975)                                                   |
| RBAC                                   | Sandhu et al. (1996)                                                         |

## Production-only items (comment as DEPLOYMENT ITEM, never fake them)

Next.js front end and its cookie; TLS on the browser–Next.js and Next.js–API links; CA-signed database TLS; key vault and key rotation; encrypted backups; quarterly manager role review; manual penetration test.
