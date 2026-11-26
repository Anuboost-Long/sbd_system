/*
 * File: CardNumber.cs
 * Implements: Guide §3.1, §3.3 card number rules: 10-19 digits, Luhn check, padded to 19 before encryption, last 4 kept.
 * Controls:   E1
 */
using System.Text.RegularExpressions;

namespace SBD.API.Services.Encryption;

public static partial class CardNumber
{
    public const int MinDigits = 10;
    public const int MaxDigits = 19;
    private const char PadCharacter = '#';

    // [Guide §3.1, §3.3] Accept a card number only if it is 10 to 19 digits and passes the Luhn check (ISO/IEC 7812-1).
    // Why: a database CHECK cannot verify it, and a mistyped number would be encrypted and stored without anyone noticing.
    // Standard: ISO/IEC 7812-1:2017; PCI DSS v4.0.1 Req 3.4.1 (masking).
    // Evidence: tests Card_LuhnInvalid_Rejected, Card_Length9_Rejected, Card_Length20_Rejected (E1).
    public static bool IsValid(string? digits) =>
        digits is { Length: >= MinDigits and <= MaxDigits } && digits.All(char.IsAsciiDigit) && PassesLuhn(digits);

    // [Guide §3.3] Pad every number to 19 characters before encrypting, so all card ciphertexts have the same length.
    // Why: ciphertext length would otherwise reveal the card's length and so its brand.
    // Standard: Guide §3.3 and PCI DSS v4.0.1 Req 3.5.1.
    // Evidence: test Card_PadsTo19_AndRoundTrips (E1).
    public static string Pad(string digits) => digits.PadRight(MaxDigits, PadCharacter);

    public static string Unpad(string padded) => padded.TrimEnd(PadCharacter);

    public static string Last4(string digits) => digits[^4..];

    public static string Mask(string last4) => $"**** **** **** {last4}";

    public static bool IsValidExpiry(string? expiry) => expiry is not null && ExpiryPattern().IsMatch(expiry);

    private static bool PassesLuhn(string digits)
    {
        var sum = 0;
        var doubleIt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            var digit = digits[i] - '0';
            if (doubleIt && (digit *= 2) > 9) digit -= 9;
            sum += digit;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    [GeneratedRegex(@"^(0[1-9]|1[0-2])/\d{2}$")]
    private static partial Regex ExpiryPattern();
}
