/*
 * File: PhoneLengthTable.cs
 * Implements: Guide §2.1 phone length checked per country code from an in-house table (209 country codes).
 * Controls:   V7
 */
namespace SBD.API.Services.Customers.Functions;

public static class PhoneLengthTable
{
    // [Guide §2.1] Check the digits after the country code against that country's allowed lengths; unknown codes are refused.
    // Why: a +7-15 digit check lets wrong-length numbers through. The 209-code table (from libphonenumber data) is built in, with no phone library.
    // Standard: ITU-T E.164.
    // Evidence: test Phone_WrongLengthForCountry_Rejected (V7).
    public static bool IsValidLength(string e164)
    {
        var digits = e164.TrimStart('+');
        for (var codeLength = 3; codeLength >= 1; codeLength--)
        {
            if (digits.Length > codeLength && PhoneLengthData.NationalLengths.TryGetValue(digits[..codeLength], out var lengths))
            {
                return lengths.Contains(digits.Length - codeLength);
            }
        }
        return false;
    }
}
