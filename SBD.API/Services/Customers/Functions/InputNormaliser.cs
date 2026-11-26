/*
 * File: InputNormaliser.cs
 * Implements: Guide §2.1 trim and Unicode NFC normalisation before any validation.
 * Controls:   V3
 */
using System.Text;

namespace SBD.API.Services.Customers.Functions;

public static class InputNormaliser
{
    // [Guide §2.1] Trim every text field and convert it to one canonical Unicode form (NFC) before it is checked; empty means "not given".
    // Why: look-alike characters (for example é written as one character or as e plus an accent) must not slip past the checks or the search.
    // Standard: OWASP ASVS 5.0 V2; OWASP Input Validation Cheat Sheet.
    // Evidence: test Name_Apostrophe_And_Accent_Accepted (V3).
    public static string? Normalise(string? value)
    {
        var normalised = value?.Trim().Normalize(NormalizationForm.FormC);
        return string.IsNullOrEmpty(normalised) ? null : normalised;
    }
}
