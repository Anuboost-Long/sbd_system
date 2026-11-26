# Security specification (from the Security Design Guide)

Single source of truth for the code. Every value below comes from the report
`Ly_K_SBD403_A3.docx`. **If code and this file disagree, the code is wrong.**
"§" = report section. Control IDs (A, V, R, E) match the evidence checklist and the test names.

Status key: **Build** = implement in this repo · **Deploy** = production item, documented only (state this in a comment where relevant, do not fake it).

---

## §1.3 Architecture

| Item                               | Spec                                                              | Status                                  |
| ---------------------------------- | ----------------------------------------------------------------- | --------------------------------------- |
| Flow                               | Browser → Next.js server → ASP.NET Core API → CustomerDb / AuthDb | API + DBs **Build**; Next.js **Deploy** |
| Only the API reaches the databases | Database port bound to localhost / internal network               | Build (docker `127.0.0.1:1433`)         |
| Two databases                      | CustomerDb (customer data), AuthDb (logins, roles, logs)          | Build                                   |

---

## §2.1 Input field specification and validation

Order: **trim → Unicode NFC normalise → allowlist + length check (server side)**. Browser checks are for usability only. Reject, never "clean up".

| Field      | Length                                    | Allowed                               | Regex (after NFC)                              | Test   |
| ---------- | ----------------------------------------- | ------------------------------------- | ---------------------------------------------- | ------ |
| First name | 1–50 (stored: required; search: optional) | Unicode letters, space, `-`, `'`      | `^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,49}$`         | V2, V3 |
| Last name  | 1–50                                      | same                                  | same                                           | V2, V3 |
| Unit       | 0–10                                      | letters, digits, `/`, `-`             | `^[A-Za-z0-9/\-]{0,10}$`                       | V2     |
| Street     | 1–60                                      | letters, digits, space, `-`, `'`, `.` | `^[\p{L}\p{M}0-9][\p{L}\p{M}0-9 '\-.]{0,59}$`  | V2     |
| State      | one of 8                                  | NSW VIC QLD SA WA TAS NT ACT          | enum                                           | V6     |
| Suburb     | controlled list                           | approved suburbs for chosen state     | lookup in Localities                           | V6     |
| Postcode   | exactly 4 digits                          | must match suburb + state             | `^\d{4}$` + lookup                             | V2, V6 |
| Phone      | `+` and 7–15 digits (≤16 chars)           | country code + valid national length  | `^\+\d{7,15}$` + in-house country length table | V7     |

- Phone lengths come from an **in-house country table**, not a third-party library (supply-chain decision).
- Accepted examples: `O'Brien`, `Zoë`, `Mary-Jane`. Rejected: `<script>`, `Smith;`, `1Smith`.

## §2.2 Prevention of malicious input (search)

| Rule                    | Value                                                                                                                      | Test |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------- | ---- |
| Malformed input         | rejected (400), not sanitised                                                                                              | V3   |
| Wildcard                | one `*` **at the end only**, after **≥3** characters; first name, last name, phone only                                    | V4   |
| `%`, `_` (and `[`)      | escaped so they are not wildcards (escaping is NOT the injection defence)                                                  | V1   |
| Required criteria       | name **or** phone (address-only search refused)                                                                            | V5   |
| Result cap              | max **50 rows**, **no paging**                                                                                             | E3   |
| Rate limit              | **30 searches / minute** per user                                                                                          | E3   |
| Daily quotas (per user) | 300 searches, 2,000 records, 20 card reveals; alert at 50%, **hard stop at 100%** → search paused until User Admin unlocks | E3   |
| Output                  | only role-permitted fields; JSON (rendered as plain text by the front end)                                                 | R1   |
| HTTP method             | search uses **POST** (personal data stays out of URLs)                                                                     | E8   |

## §2.3 Data transport

| Rule          | Value                                                                                         | Status                                                       |
| ------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| TLS           | **TLS 1.3 only**, AES-256-GCM, ECDHE P-384; certs ECDSA P-384 or RSA ≥3072                    | API Kestrel: **Build**; other links **Deploy**               |
| HTTPS         | redirect + **HSTS**                                                                           | Build                                                        |
| API caller    | only the Next.js server: **API key** + **IP allowlist** (address proves origin, not identity) | Build (E6)                                                   |
| DB connection | certificate-checked, TLS 1.3 enforced in server settings                                      | Deploy (dev uses Docker self-signed cert; say so in comment) |
| Standards     | ISM-1139, ISM-1369, ISM-1372; exceeds NIST SP 800-52r2 TLS 1.2 baseline                       |                                                              |

## §2.4 User authentication and credential storage

| Rule              | Value                                                                                                             | Test                                          |
| ----------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------------------- |
| Username          | unique, 3–32 chars, letters/digits/`.`/`_`                                                                        | —                                             |
| Password length   | min **15**; min **8 if MFA** enabled; max ≥ **64**                                                                | A3                                            |
| Composition rules | **none**                                                                                                          | A3                                            |
| Breached list     | reject passwords on a breached/common list                                                                        | A4                                            |
| Hashing           | ASP.NET Core Identity, **PBKDF2-HMAC-SHA512, 600,000 iterations**, salted (not Argon2id: avoids extra dependency) | A1, A2                                        |
| Storage           | separate login database (AuthDb)                                                                                  | A1                                            |
| MFA               | **TOTP** required for **Accounting, Privileged, UserAdmin**; Normal relies on long password                       | A8                                            |
| Session token     | random **256-bit**, stored only as **SHA-256 hash**                                                               | A9                                            |
| Timeouts          | **15 min idle**, **8 h absolute**; logout ends session                                                            | A10                                           |
| Cookie            | HttpOnly, Secure, SameSite, held by Next.js                                                                       | **Deploy** (API returns bearer token in demo) |

## §2.5 Protection against automated login attempts

| Rule          | Value                                                                                                                     | Test |
| ------------- | ------------------------------------------------------------------------------------------------------------------------- | ---- |
| Error message | one generic message, similar timing (unknown user = wrong password)                                                       | A5   |
| Lockout       | **5 failures → 15 min** (primary control)                                                                                 | A6   |
| Rate limit    | **10 login attempts / minute per IP**                                                                                     | A7   |
| CAPTCHA       | **Cloudflare Turnstile** after **3** failures, verified server-side; **verification failure = login refused** (fail-safe) | A8b  |
| Note          | stricter than NIST's 100 limit, accepts brief DoS risk                                                                    |      |

## §2.6 Account recovery

| Rule     | Value                                                                      | Status           |
| -------- | -------------------------------------------------------------------------- | ---------------- |
| Who      | staff only; resets done by **User Admin** after out-of-band identity check | Build (endpoint) |
| On reset | force password change, **revoke all sessions**, **log**                    | Build            |
| Rejected | secret questions, email self-service                                       | —                |

---

## §3.1 Data field specification (storage)

Database repeats §2.1 limits as a second barrier (CHECK constraints, FK).

| Table.Field                          | Stored                 | Rule                                                                              |
| ------------------------------------ | ---------------------- | --------------------------------------------------------------------------------- |
| Customers.FirstName / LastName       | NVARCHAR(50) required  | letters, space, `-`, `'`                                                          |
| Customers.Unit                       | NVARCHAR(10) optional  | letters, digits, `/`, `-`                                                         |
| Customers.Street                     | NVARCHAR(60) required  | letters, digits, space, `-`, `'`, `.`                                             |
| Customers.LocalityId                 | FK required            | must exist in Localities                                                          |
| Customers.Phone                      | VARCHAR(16) required   | `+` and 7–15 digits                                                               |
| Localities.Suburb                    | NVARCHAR(46)           | letters, space, `-`, `'`                                                          |
| Localities.State                     | VARCHAR(3)             | 8 codes                                                                           |
| Localities.Postcode                  | CHAR(4)                | 4 digits (keeps leading zeros)                                                    |
| Localities (Suburb, State, Postcode) | UNIQUE                 |                                                                                   |
| Customers.MedicalStatusEnc           | encrypted, VARCHAR(48) | code 1–6: Sick, Healthy, Cancer, Deceased, Flu, Covid (equal length hides status) |
| Customers.CardNumberEnc              | encrypted, VARCHAR(80) | 10–19 digits, **Luhn-checked** (ISO/IEC 7812-1)                                   |
| Customers.CardLast4                  | CHAR(4) plain          | masked display                                                                    |
| Customers.CardExpiryEnc              | encrypted, VARCHAR(64) | MM/YY                                                                             |

## §3.2 Database access and SQL injection prevention

| Rule           | Value                                                                                                                                      | Test         |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------ | ------------ |
| Queries        | **parameterised only** (EF Core LINQ / `EF.Functions.Like` with parameters). **No** `FromSqlRaw`/`ExecuteSqlRaw` with string concatenation | V1           |
| Escaping       | not relied on; only stops `%` `_` acting as wildcards                                                                                      | V1           |
| Login required | no query before a valid session                                                                                                            | A11          |
| DB logins      | one read-only login per role view; separate login (`app_identity`) for AuthDb                                                              | R4           |
| Errors         | generic message to client; no SQL / stack trace                                                                                            | V9           |
| Secrets        | `.env` only, excluded from git **and** from the ZIP; `.env.example` with placeholders                                                      | E9 (risk R7) |

## §3.3 Encryption at rest

| Rule            | Value                                                                               | Test                                   |
| --------------- | ----------------------------------------------------------------------------------- | -------------------------------------- |
| Algorithm       | **AES-256-GCM** (`System.Security.Cryptography.AesGcm`)                             | E1                                     |
| Nonce           | random 12 bytes per value                                                           | E1 (`SameValue_DifferentCiphertext`)   |
| Tag             | 16 bytes; tampered value rejected                                                   | E2                                     |
| Associated data | row ID + column name → value copied to another row is rejected                      | E2                                     |
| Format          | `v1:` + Base64(nonce ‖ ciphertext ‖ tag) (version prefix supports key rotation)     | E1                                     |
| Key             | only the API holds it (`.env` `FieldEncryption__Key`); production: vault + rotation | key: Build; vault/rotation: **Deploy** |
| Backups         | encrypted                                                                           | **Deploy**                             |
| Rejected        | TDE alone (DB logins would still see plain text)                                    | —                                      |

---

## §4.1 User groups and access matrix

| Data                      | Normal |     Accounting      | Privileged | UserAdmin |
| ------------------------- | :----: | :-----------------: | :--------: | :-------: |
| Name, address, phone      |   ✔    |          ✔          |     ✔      |     ✘     |
| Card (last 4)             |   ✘    |          ✔          |     ✔      |     ✘     |
| Card full number + expiry |   ✘    | ✔ **logged reveal** |     ✔      |     ✘     |
| Medical status            |   ✘    |          ✘          |     ✔      |     ✘     |
| Manage accounts           |   ✘    |          ✘          |     ✘      |     ✔     |

Exactly **one role per user**. UserAdmin is administrative, not a data group.

## §4.2 User identification

| Rule        | Value                                                                     | Test                 |
| ----------- | ------------------------------------------------------------------------- | -------------------- |
| Accounts    | one personal account, one role                                            | DB8 (database check) |
| Role source | read from AuthDb **on every request**, never from the client/token claims | R2                   |
| Process     | manager approves, IT (UserAdmin) assigns                                  | —                    |
| Disable     | on manager's written request, or **90 days** without login                | E10                  |

## §4.3 Enforcement of access rights (enforced twice)

| Layer    | Rule                                                                                                                    | Test |
| -------- | ----------------------------------------------------------------------------------------------------------------------- | ---- |
| API      | returns **one DTO per role** with only permitted fields                                                                 | R1   |
| Database | one view per role (`vw_Normal`, `vw_Accounting`, `vw_Privileged`), each readable only by its own login; base table DENY | R4   |
| Routes   | **deny by default**; every route tested for every role                                                                  | R3   |

## §4.4 Prevention of privilege escalation

| Rule                                                                          | Test                 |
| ----------------------------------------------------------------------------- | -------------------- |
| Client-supplied role ignored                                                  | R2                   |
| Card reveal checked on the server + logged                                    | R5                   |
| UserAdmin: no customer data                                                   | R6                   |
| UserAdmin: cannot change own role / account                                   | R6                   |
| UserAdmin: needs MFA + **manager approval reference** + internal network only | R6                   |
| Every change logged                                                           | R6                   |
| Quarterly manager re-confirmation                                             | **Deploy** (process) |

---

## §5 General security design

| Principle            | Where in code                                                                             |
| -------------------- | ----------------------------------------------------------------------------------------- |
| Defence in depth     | validation + parameterised queries + DB CHECKs; API DTOs + DB views                       |
| Least privilege      | one role per user; view-limited DB logins; `app_identity` cannot edit logs or permissions |
| Fail-safe defaults   | fallback policy = deny; unknown role → 403; CAPTCHA failure → login refused               |
| Small attack surface | API not public; DB on localhost; admin endpoints internal-network only                    |
| Separation of duties | UserAdmin sees no data; DB trigger blocks mixing permissions                              |

**Logging:** log logins, failures, lockouts, role changes, card reveals, medical access.
**Never log:** passwords, card numbers, medical status, typed search names. Users see generic errors only.

**Release checks (DevSecOps / SSDF):** authorisation tests, injection tests and dependency check (`dotnet list package --vulnerable`) run before release and block on failure. Build: `scripts/release_check.sh` (+ optional GitHub Actions file).

## §6 Risk controls that need code

| Risk                    | Code control                                                                                                  |
| ----------------------- | ------------------------------------------------------------------------------------------------------------- |
| R1 SQL injection        | §3.2                                                                                                          |
| R2 Password guessing    | §2.5                                                                                                          |
| R3 Privilege escalation | §4.2–4.4                                                                                                      |
| R4 Bulk harvesting      | §2.2 caps + daily quotas + **alphabet-walk alert** + SearchLog stores **HMAC-SHA-256 fingerprint**, not names |
| R6 DB theft             | §3.3                                                                                                          |
| R7 Leaked secrets       | `.env` excluded; no-secrets check script                                                                      |
| R8 Insider misuse       | AuditLog (append-only)                                                                                        |
