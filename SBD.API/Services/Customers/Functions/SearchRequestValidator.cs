/*
 * File: SearchRequestValidator.cs
 * Implements: Guide §2.1, §2.2 server-side allowlist, length, wildcard, locality and name-or-phone rules for search.
 * Controls:   V2, V3, V4, V5, V6, V7
 */
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SBD.API.Services.Customers.Dtos;

namespace SBD.API.Services.Customers.Functions;

public partial class SearchRequestValidator(CustomerAccess access)
{
    private static readonly string[] States = ["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];
    private const int MinWildcardPrefix = 3;

    public async Task<(SearchCriteria? Criteria, Dictionary<string, string[]> Errors)> ValidateAsync(
        SearchRequest request, string? connectionName)
    {
        var errors = new Dictionary<string, string[]>();
        void Fail(string field, string message) => errors[field] = [message];

        // [Guide §2.2] The request has no paging fields; any unexpected field, including page, skip or offset, is refused.
        // Why: results are capped at 50 rows with no paging, so a caller cannot walk through the whole table.
        // Standard: OWASP ASVS 5.0 V2; Guide §2.2.
        // Evidence: test Paging_Refused (E3).
        if (request.UnknownFields is { Count: > 0 })
            Fail("request", "Unexpected field. Paging is not supported.");

        var firstName = ParseName(request.FirstName, "firstName", Fail);
        var lastName = ParseName(request.LastName, "lastName", Fail);
        var phone = ParsePhone(request.Phone, Fail);

        // [Guide §2.1] Reject, never clean up: each field is checked against an allowlist pattern and its length after trim and NFC.
        // Why: the browser checks are only for usability; this server-side list is the real barrier (the database repeats it).
        // Standard: OWASP ASVS 5.0 V2; OWASP Input Validation Cheat Sheet.
        // Evidence: tests LastName_50Chars_Accepted, LastName_51Chars_Rejected, Name_DisallowedChars_Rejected (V2, V3).
        var unit = Check(InputNormaliser.Normalise(request.Unit), UnitPattern(), "unit", Fail);
        var street = Check(InputNormaliser.Normalise(request.Street), StreetPattern(), "street", Fail);
        var suburb = Check(InputNormaliser.Normalise(request.Suburb), SuburbPattern(), "suburb", Fail);
        var postcode = Check(InputNormaliser.Normalise(request.Postcode), PostcodePattern(), "postcode", Fail);
        var state = InputNormaliser.Normalise(request.State);
        if (state is not null && !States.Contains(state)) { Fail("state", "Choose a valid state."); state = null; }

        // [Guide §2.2] A search needs a name or a phone; an address alone is refused.
        // Why: address-only searches would let someone list every customer in a suburb.
        // Standard: Guide §2.2 and risk R4.
        // Evidence: test AddressOnlySearch_Rejected (V5).
        if (firstName is null && lastName is null && phone is null && !errors.ContainsKey("request"))
            Fail("criteria", "Enter a name or a phone number.");

        // [Guide §2.1, §3.1] If a state, suburb or postcode is given, that combination must exist in the approved locality list.
        // Why: dropdowns can be bypassed, so the server checks again; this blocks values such as Richmond, QLD, 3121.
        // Standard: OWASP ASVS 5.0 V2; Guide §2.1.
        // Evidence: tests InvalidLocality_Rejected, Postcode_NotFourDigits_Rejected (V6).
        if (errors.Count == 0 && (state is not null || suburb is not null || postcode is not null))
        {
            var localities = access.Localities(connectionName);
            // [Guide §3.2] parameterised
            var exists = localities is not null && await localities.AnyAsync(l =>
                (state == null || l.State == state) && (suburb == null || l.Suburb == suburb) && (postcode == null || l.Postcode == postcode));
            if (!exists) Fail("locality", "That suburb, state and postcode do not match.");
        }

        return errors.Count > 0
            ? (null, errors)
            : (new SearchCriteria(firstName, lastName, phone, unit, street, state, suburb, postcode), errors);
    }

    // [Guide §2.2] A wildcard is one * at the very end, after at least 3 characters (3 digits for a phone), and only on first name, last name and phone.
    // Why: limits bulk harvesting (risk R4); `*`, `Sm*`, `S*m` and `**` are refused, and `+61*` is refused because a country code alone matches too many people.
    // Standard: Guide §2.2 and risk R4.
    // Evidence: test Wildcard_Rules_Enforced (V4).
    private static SearchTerm? ParseName(string? raw, string field, Action<string, string> fail)
    {
        var value = InputNormaliser.Normalise(raw);
        if (value is null) return null;

        var isPrefix = value.EndsWith('*');
        var text = isPrefix ? value[..^1] : value;
        if (!NamePattern().IsMatch(text) || (isPrefix && text.Length < MinWildcardPrefix))
        {
            fail(field, isPrefix && text.Length < MinWildcardPrefix
                ? "Enter at least 3 characters before the *."
                : "Use letters, spaces, apostrophes and hyphens only (up to 50).");
            return null;
        }
        return new SearchTerm(text, isPrefix);
    }

    private static SearchTerm? ParsePhone(string? raw, Action<string, string> fail)
    {
        var value = InputNormaliser.Normalise(raw);
        if (value is null) return null;

        var isPrefix = value.EndsWith('*');
        var text = isPrefix ? value[..^1] : value;
        var valid = isPrefix
            ? text.Count(char.IsAsciiDigit) >= MinWildcardPrefix && PhonePrefixPattern().IsMatch(text)
            : PhonePattern().IsMatch(text) && PhoneLengthTable.IsValidLength(text);
        if (!valid)
        {
            fail("phone", "Enter a phone number such as +61412345678, with the right number of digits for the country (at least 3 digits before a *).");
            return null;
        }
        return new SearchTerm(text, isPrefix);
    }

    private static string? Check(string? value, Regex pattern, string field, Action<string, string> fail)
    {
        if (value is null) return null;
        if (pattern.IsMatch(value)) return value;
        fail(field, "That value contains characters or a length that is not allowed.");
        return null;
    }

    [GeneratedRegex(@"^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,49}$")] private static partial Regex NamePattern();
    [GeneratedRegex(@"^[A-Za-z0-9/\-]{1,10}$")] private static partial Regex UnitPattern();
    [GeneratedRegex(@"^[\p{L}\p{M}0-9][\p{L}\p{M}0-9 '\-.]{0,59}$")] private static partial Regex StreetPattern();
    [GeneratedRegex(@"^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,45}$")] private static partial Regex SuburbPattern();
    [GeneratedRegex(@"^\d{4}$")] private static partial Regex PostcodePattern();
    [GeneratedRegex(@"^\+\d{7,15}$")] private static partial Regex PhonePattern();
    [GeneratedRegex(@"^\+\d{2,14}$")] private static partial Regex PhonePrefixPattern();
}
