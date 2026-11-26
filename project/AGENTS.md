# Instructions for the coding agent

Project: SBD403 Assessment 3, the source code that goes with a Security Design Guide.
Stack: ASP.NET Core Web API (.NET LTS), EF Core, ASP.NET Core Identity, SQL Server 2022 (Docker), xUnit.
The Next.js front end is **not** built; it is a production design item.

The marker reads this code to check that **every control in the design guide is really implemented**,
and that each one is **commented with the guide decision and the standard it follows**.
Comments are part of the mark (Criterion 3). Write them for a lecturer, not for a developer.

## 1. Read first

1. `SECURITY_SPEC.md`: every security value and rule. **This is the source of truth.** Never change a value
   (lengths, limits, iterations, timeouts, roles) on your own. If something can't be built as specified,
   stop and report it.
2. `db_model_spec.md`: tables, fields, types for EF Core models.
3. `database/*.sql`: the existing schema. The API maps to it; **do not run EF migrations against AuthDb or CustomerDb**.

## 2. Comment format (use exactly this)

### 2a. On every security method, class or configuration block

```csharp
// [Guide §2.5] Lock the account for 15 minutes after 5 failed logins.
// Why: slows password guessing; lockout stays the main control because bots can solve CAPTCHAs.
// Standard: OWASP ASVS 5.0 V6.3.1; NIST SP 800-63B-4.
// Evidence: test SixthAttempt_AccountLocked (A6).
```

Four lines, always in this order:

| Line           | Content                                                                                                  |
| -------------- | -------------------------------------------------------------------------------------------------------- |
| `[Guide §x.y]` | report section + **what** the code does, in plain words with the technical term in brackets where useful |
| `Why:`         | the security reason or the decision made in the guide (one line)                                         |
| `Standard:`    | IDs from the **allowed list in section 4** only                                                          |
| `Evidence:`    | test name(s) + control ID from `SECURITY_SPEC.md`                                                        |

### 2b. For production-only items (status **Deploy** in the spec)

```csharp
// [Guide §2.3] DEPLOYMENT ITEM, not active in this demo:
// in production the database connection uses a CA-signed certificate (Encrypt=Strict, TLS 1.3).
// Demo uses the Docker self-signed certificate (TrustServerCertificate=true) on localhost only.
```

Never pretend a Deploy item is implemented.

### 2c. On every file that holds security code, add a header

```csharp
/*
 * File: PasswordPolicyValidator.cs
 * Implements: Guide §2.4 password rules (length 15 / 8 with MFA, max >= 64,
 *             no composition rules, breached-password list).
 * Controls:   A3, A4
 */
```

### 2d. Style rules

- Plain English. Technical term in brackets: "random value per entry (nonce)".
- Say **what** and **why**, not how C# works. No "this loops over the list".
- Use the exact numbers from the spec (15 min, 5 failures, 600,000, 50 rows).
- Keep each comment block to 4–6 lines. No essay comments.
- Every place where an attack is blocked gets a comment, including the `return BadRequest/Forbid/Unauthorized` line
  if it is not obvious.
- Do **not** mention AI, the agent, or these instructions in code comments.

## 3. What must be commented (checklist: every row needs a comment block)

| Area                                                                           | Where in code                        | Guide §     | Control IDs |
| ------------------------------------------------------------------------------ | ------------------------------------ | ----------- | ----------- |
| Input normalisation (trim + NFC)                                               | validator / model binder             | 2.1         | V3          |
| Field allowlist + length rules                                                 | validators per field                 | 2.1         | V2, V3      |
| Locality must match the list                                                   | locality validator / service         | 2.1, 3.1    | V6          |
| Phone per-country length table                                                 | phone validator + table              | 2.1         | V7          |
| Wildcard rules + `%` `_` `[` escaping                                          | search query builder                 | 2.2         | V4, V1      |
| Name-or-phone required                                                         | search request validator             | 2.2         | V5          |
| 50-row cap, no paging                                                          | search service                       | 2.2         | E3          |
| Rate limits (10/min login, 30/min search)                                      | `Program.cs` rate limiter setup      | 2.2, 2.5    | A7, E3      |
| Daily quotas + soft/hard limit + pause                                         | quota service                        | 2.2, 6 (R4) | E3          |
| Alphabet-walk detection + HMAC-SHA-256 fingerprint                             | search log service                   | 6 (R4)      | E4, E5      |
| Parameterised queries                                                          | **every** EF query on customer data  | 3.2         | V1          |
| Generic error handler                                                          | exception middleware                 | 3.2, 5      | V9          |
| HTTPS, HSTS, TLS 1.3 Kestrel config                                            | `Program.cs` / `appsettings`         | 2.3         | E7, E8      |
| Security headers                                                               | middleware                           | 2.3         | E8          |
| API key + IP allowlist                                                         | middleware                           | 2.3         | E6          |
| Identity password options + 600,000 iterations                                 | `Program.cs` Identity setup          | 2.4         | A1, A2, A3  |
| Breached-password validator                                                    | custom `IPasswordValidator`          | 2.4         | A4          |
| TOTP MFA required for 3 roles                                                  | login service                        | 2.4         | A8          |
| Session token create (256-bit) + SHA-256 store                                 | session service                      | 2.4         | A9          |
| Idle 15 min / absolute 8 h / logout                                            | session auth handler                 | 2.4         | A10         |
| Generic login failure + similar timing                                         | login service                        | 2.5         | A5          |
| Lockout 5 → 15 min                                                             | Identity lockout options             | 2.5         | A6          |
| Turnstile after 3 failures, fail-safe                                          | CAPTCHA service                      | 2.5         | A8b         |
| Admin reset: force change, revoke sessions, log                                | admin service                        | 2.6         | R6          |
| Field encryption AES-256-GCM, nonce, tag, AAD, `v1:`                           | encryption service                   | 3.3         | E1, E2      |
| Luhn check, pad to 19, keep last 4                                             | card helper                          | 3.1, 3.3    | E1          |
| DB connection per role (view-limited logins)                                   | connection factory / DbContext setup | 3.2, 4.3    | R4          |
| Secrets from `.env` only, never overriding real env vars                       | `.env` loader                        | 3.2 (R7)    | E9          |
| Role read from AuthDb every request                                            | auth handler                         | 4.2         | R2          |
| Permission-based policies, deny by default (fallback policy)                   | `Program.cs` authorisation           | 4.3, 5      | R3          |
| One DTO per role                                                               | DTO mapping                          | 4.1, 4.3    | R1          |
| Card reveal: server check + audit log + daily 20 limit                         | reveal endpoint                      | 3.3, 4.4    | R5          |
| UserAdmin rules (no data, no self-change, approval ref, MFA, internal network) | admin endpoints                      | 4.4         | R6          |
| Role change + audit row in **one transaction**                                 | admin service                        | 4.4         | R6          |
| 90-day inactivity disable                                                      | background job                       | 4.2         | E10         |
| Audit logging, never logging secrets                                           | audit service                        | 5           | —           |
| Release checks                                                                 | `scripts/release_check.sh`           | 5           | —           |

## 4. Allowed standard references (verified, use only these)

Do **not** invent requirement numbers. If nothing below fits, cite only the guide section.

| Topic                                         | Use                                                                                   |
| --------------------------------------------- | ------------------------------------------------------------------------------------- |
| Password length / no composition / max length | OWASP ASVS 5.0 V6.2.1, V6.2.5, V6.2.9; NIST SP 800-63B-4                              |
| Breached passwords                            | OWASP ASVS 5.0 V6.2.12                                                                |
| Lockout / brute force                         | OWASP ASVS 5.0 V6.3.1, V6.1.1; NIST SP 800-63B-4                                      |
| MFA                                           | OWASP ASVS 5.0 V6.3.3                                                                 |
| Generic login errors                          | OWASP ASVS 5.0 V6.3.8                                                                 |
| Password hashing                              | OWASP ASVS 5.0 V11.4.2; OWASP Password Storage Cheat Sheet                            |
| Session token randomness                      | OWASP ASVS 5.0 V11.5.1; OWASP Session Management Cheat Sheet                          |
| Parameterised queries                         | OWASP ASVS 5.0 V1.2.4; OWASP SQL Injection Prevention Cheat Sheet                     |
| Input validation                              | OWASP ASVS 5.0 V2 (Validation and Business Logic); OWASP Input Validation Cheat Sheet |
| Access control, deny by default               | OWASP ASVS 5.0 V8.2.1                                                                 |
| Field-level access                            | OWASP ASVS 5.0 V8.2.3                                                                 |
| Server-side role decision                     | OWASP ASVS 5.0 V8.3.1                                                                 |
| Encryption (AES-GCM, nonce, keys)             | OWASP ASVS 5.0 V11.3.2, V11.3.3, V11.3.4; ASD ISM (Sep 2026)                          |
| Card data                                     | PCI DSS v4.0.1 Req 3.4.1 (masking), Req 3.5.1 (stored PAN unreadable)                 |
| TLS                                           | ASD ISM-1139, ISM-1369, ISM-1372; NIST SP 800-52 Rev. 2                               |
| Security headers / errors / logging           | OWASP HTTP Headers, Error Handling, Logging Cheat Sheets; OWASP ASVS 5.0 V16          |
| Separation of duties, one account per person  | ISO/IEC 27001:2022                                                                    |
| Phone format                                  | ITU-T E.164                                                                           |
| Card number length / Luhn                     | ISO/IEC 7812-1:2017                                                                   |
| Design principles                             | Saltzer & Schroeder (1975)                                                            |
| RBAC                                          | Sandhu et al. (1996)                                                                  |

## 5. Code rules (security, non-negotiable)

- **No raw SQL with string building.** No `FromSqlRaw`, `ExecuteSqlRaw`, or `SqlCommand` with concatenated input.
  Use LINQ or `FromSqlInterpolated` only. Comment each customer query with `[Guide §3.2] parameterised`.
- **No secrets in code, `appsettings*.json`, tests or comments.** Read from environment / `.env`.
  `.env` is in `.gitignore` and must not go into the submission ZIP. Keep `.env.example` with placeholders.
- **Synthetic data only.** Card numbers must be test numbers that pass Luhn (e.g. 4111111111111111). No real people.
- Never log passwords, tokens, card numbers, expiry, medical status or typed search names.
- Error responses are generic (`ProblemDetails` without stack traces or SQL).
- Authorisation: fallback policy = authenticated + deny; every endpoint has an explicit permission policy.
- Role/permissions are read from AuthDb on every request; ignore any role in headers, body, query or token claims.

## 6. Tests

- xUnit test names must match the control IDs in `SECURITY_SPEC.md` / `EVIDENCE_CHECKLIST.md` (e.g. `SixthAttempt_AccountLocked`).
- Each test gets a one-line comment: `// A6 – Guide §2.5 lockout`.
- Must include the headline injection tests (V1):
  `Injection_InLastName_Rejected` (`' OR '1'='1` → 400),
  `Injection_AtQueryLayer_ReturnsNoRows` (bypass validator → 0 rows, not all rows),
  and log the EF Core SQL so the `@p0` parameter is visible.
- Route matrix test (R3): every endpoint × every role (+ anonymous) → expected status.
- Report only **real** results. If a test fails, fix the code or report the failure. Never weaken a test to pass.

## 7. Fix the existing SQL comments

The `database/*.sql` comments already use `[Guide x.y]`. Change them to `[Guide §x.y]` so they match the C# format,
and keep the section numbers as they are. Do not change any SQL logic without asking.

## 8. When report and code don't match

Don't silently pick one. Add an entry to `MISMATCHES.md` (what the guide says, what the code does, suggested fix)
and tell the user. Known items already decided:

- Next.js, HttpOnly cookie, TLS on the Next.js and database links, key vault, key rotation, encrypted backups,
  quarterly role review → **Deploy** (comment as in 2b).
- Demo API returns the session token as a bearer token (Next.js would hold it in production).

## 9. Done means

- [ ] Every row in section 3 has a comment block in the 2a format
- [ ] Every security file has a 2c header
- [ ] All standard IDs come from section 4
- [ ] No secrets anywhere (`grep -ri "password=" --include=*.cs --include=*.json` returns nothing real)
- [ ] `dotnet test` passes; output saved for Appendix B
- [ ] `MISMATCHES.md` is empty or every item has been discussed with the user
