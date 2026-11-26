/*
 * File: CustomerSearchService.cs
 * Implements: Guide §2.2, §3.2, §4.3 parameterised search through the role's own view, 50-row cap, one DTO per role.
 * Controls:   V1, E3, R1, R4
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Models.CustomerDb;
using SBD.API.Models.CustomerDb.Views;
using SBD.API.Services.Audit;
using SBD.API.Services.Customers.Dtos;
using SBD.API.Services.Customers.Functions;
using SBD.API.Services.Encryption;
using SBD.API.Models.AuthDb;

namespace SBD.API.Services.Customers;

public record SearchOutcome(IReadOnlyList<object>? Results, bool Forbidden = false);

public class CustomerSearchService(CustomerAccess access, FieldEncryptionService encryption, IAuditLogger audit)
{
    public const int MaxRows = 50;

    // [Guide §4.3] Pick the database connection from the user's role (read from AuthDb), query only that role's view, and return only that role's DTO.
    // Why: rights are enforced twice. The API sends only permitted fields, and the database login behind each view cannot read other columns.
    // An unknown or missing connection gets 403.
    // Standard: OWASP ASVS 5.0 V8.2.3; Sandhu et al. (1996).
    // Evidence: tests Normal_SeesNoCardOrMedical, Accounting_SeesMaskedCard_NoMedical, Privileged_SeesAllFields (R1).
    public async Task<SearchOutcome> SearchAsync(string userId, string? connectionName, SearchCriteria criteria)
    {
        switch (connectionName)
        {
            case CustomerAccess.NormalConnection:
                var normal = await QueryAsync(access.Normal.Customers, criteria);
                return new SearchOutcome([.. normal.Select(r => new NormalResult(
                    r.CustomerId, r.FirstName, r.LastName, r.Unit, r.Street, r.Suburb, r.State, r.Postcode, r.Phone))]);

            case CustomerAccess.AccountingConnection:
                var accounting = await QueryAsync(access.Accounting.Customers, criteria);
                return new SearchOutcome([.. accounting.Select(r => new AccountingResult(
                    r.CustomerId, r.FirstName, r.LastName, r.Unit, r.Street, r.Suburb, r.State, r.Postcode, r.Phone,
                    CardNumber.Mask(r.CardLast4)))]);

            case CustomerAccess.PrivilegedConnection:
                var privileged = await QueryAsync(access.Privileged.Customers, criteria);
                var results = privileged.Select(r => new PrivilegedResult(
                    r.CustomerId, r.FirstName, r.LastName, r.Unit, r.Street, r.Suburb, r.State, r.Postcode, r.Phone,
                    CardNumber.Mask(r.CardLast4),
                    CardNumber.Unpad(encryption.Decrypt(r.CardNumberEnc, r.CustomerId, EncryptedColumns.CardNumber)),
                    encryption.Decrypt(r.CardExpiryEnc, r.CustomerId, EncryptedColumns.CardExpiry),
                    ((MedicalStatus)int.Parse(encryption.Decrypt(r.MedicalStatusEnc, r.CustomerId, EncryptedColumns.MedicalStatus))).ToString())).ToList();

                // [Guide §5] Every customer whose medical status is returned gets one MedicalViewed audit row.
                // Why: medical data is the most sensitive field, so each disclosure must be traceable to a person and a customer.
                // Standard: OWASP ASVS 5.0 V16; OWASP Logging Cheat Sheet.
                // Evidence: test Privileged_Search_AuditsMedicalViewed.
                await audit.LogCustomerAccessAsync(AuditAction.MedicalViewed, userId, privileged.Select(r => r.CustomerId));
                return new SearchOutcome([.. results]);

            default:
                return new SearchOutcome(null, Forbidden: true);
        }
    }

    // [Guide §3.2] Parameterised query: the SQL is fixed and every value is sent as a parameter, so input is data, never a command.
    // Why: this is the SQL injection defence; escaping % and _ only stops wildcards.
    // Standard: OWASP ASVS 5.0 V1.2.4; OWASP SQL Injection Prevention Cheat Sheet.
    // Evidence: tests Injection_InLastName_Rejected, Injection_AtQueryLayer_ReturnsNoRows (V1).
    //
    // [Guide §2.2] Return at most 50 rows, ordered by name, no paging.
    // Why: limits how much one request can reveal (risk R4).
    // Standard: Guide §2.2.
    // Evidence: test ResultCap_50 (E3).
    private static Task<List<TRow>> QueryAsync<TRow>(IQueryable<TRow> rows, SearchCriteria c) where TRow : class, ICustomerRow
    {
        var query = rows.AsNoTracking();

        if (c.LastName is { } last)
            query = last.IsPrefix ? query.Where(r => EF.Functions.Like(r.LastName, EscapeLike(last.Value) + "%", "\\")) : query.Where(r => r.LastName == last.Value);
        if (c.FirstName is { } first)
            query = first.IsPrefix ? query.Where(r => EF.Functions.Like(r.FirstName, EscapeLike(first.Value) + "%", "\\")) : query.Where(r => r.FirstName == first.Value);
        if (c.Phone is { } phone)
            query = phone.IsPrefix ? query.Where(r => EF.Functions.Like(r.Phone, EscapeLike(phone.Value) + "%", "\\")) : query.Where(r => r.Phone == phone.Value);
        if (c.Unit is { } unit) query = query.Where(r => r.Unit == unit);
        if (c.Street is { } street) query = query.Where(r => r.Street == street);
        if (c.State is { } state) query = query.Where(r => r.State == state);
        if (c.Suburb is { } suburb) query = query.Where(r => r.Suburb == suburb);
        if (c.Postcode is { } postcode) query = query.Where(r => r.Postcode == postcode);

        return query.OrderBy(r => r.LastName).ThenBy(r => r.FirstName).ThenBy(r => r.CustomerId).Take(MaxRows).ToListAsync();
    }

    // [Guide §2.2] Put a backslash before \, %, _ and [ so a typed prefix is matched literally.
    // Why: otherwise a user could type % or _ to widen a prefix search.
    // Standard: Guide §2.2 (escaping is not the injection defence, see the parameterised query above).
    // Evidence: test Wildcard_PercentAndUnderscore_AreLiteral (V1).
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_").Replace("[", "\\[");
}
