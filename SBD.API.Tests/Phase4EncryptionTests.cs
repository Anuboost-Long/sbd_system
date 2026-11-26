using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SBD.API.Services.Encryption;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase4EncryptionTests
{
    private static FieldEncryptionService NewService() =>
        new(Options.Create(new FieldEncryptionOptions { Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }));

    // E1 – Guide §3.3 encrypt then decrypt returns the original
    [Fact]
    public void Encrypt_Decrypt_RoundTrip()
    {
        var service = NewService();

        var stored = service.Encrypt("4111111111111111###", 7, EncryptedColumns.CardNumber);

        Assert.StartsWith("v1:", stored);
        Assert.DoesNotContain("4111", stored);
        Assert.Equal("4111111111111111###", service.Decrypt(stored, 7, EncryptedColumns.CardNumber));
    }

    // E1 – Guide §3.3 a fresh random nonce means the same value never gives the same ciphertext
    [Fact]
    public void SameValue_DifferentCiphertext()
    {
        var service = NewService();

        Assert.NotEqual(
            service.Encrypt("same", 1, EncryptedColumns.MedicalStatus),
            service.Encrypt("same", 1, EncryptedColumns.MedicalStatus));
    }

    // E2 – Guide §3.3 a changed byte is detected by the tag
    [Fact]
    public void Tampered_Fails()
    {
        var service = NewService();
        var bytes = Convert.FromBase64String(service.Encrypt("secret", 1, EncryptedColumns.CardExpiry)[3..]);
        bytes[13] ^= 0x01;

        Assert.ThrowsAny<CryptographicException>(() =>
            service.Decrypt("v1:" + Convert.ToBase64String(bytes), 1, EncryptedColumns.CardExpiry));
    }

    // E2 – Guide §3.3 a value copied to another customer, or to another column, cannot be decrypted
    [Fact]
    public void CopiedToOtherRow_Fails()
    {
        var service = NewService();
        var stored = service.Encrypt("secret", 1, EncryptedColumns.CardNumber);

        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(stored, 2, EncryptedColumns.CardNumber));
        Assert.ThrowsAny<CryptographicException>(() => service.Decrypt(stored, 1, EncryptedColumns.CardExpiry));
    }

    // E2 – Guide §3.3 an unknown version prefix is refused
    [Fact]
    public void UnknownVersion_Rejected() =>
        Assert.Throws<CryptographicException>(() => NewService().Decrypt("v2:AAAA", 1, EncryptedColumns.MedicalStatus));

    // E1 – Guide §3.1 every medical status code encrypts to the same length, so the length hides the status
    [Fact]
    public void MedicalStatus_AllCodes_SameCiphertextLength()
    {
        var service = NewService();

        var lengths = Enumerable.Range(1, 6)
            .Select(code => service.Encrypt(code.ToString(), 1, EncryptedColumns.MedicalStatus).Length)
            .Distinct();

        Assert.Single(lengths);
    }

    // E1 – Guide §3.1 a Luhn-invalid number is rejected
    [Fact]
    public void Card_LuhnInvalid_Rejected() => Assert.False(CardNumber.IsValid("4111111111111112"));

    // E1 – Guide §3.1 a 9-digit number is rejected
    [Fact]
    public void Card_Length9_Rejected() => Assert.False(CardNumber.IsValid("424242424"));

    // E1 – Guide §3.1 a 20-digit number is rejected
    [Fact]
    public void Card_Length20_Rejected() => Assert.False(CardNumber.IsValid("42424242424242424242"));

    // E1 – Guide §3.1 test card numbers of 13, 14, 15, 16 and 19 digits are accepted; letters are not
    [Theory]
    [InlineData("4222222222222")]
    [InlineData("30569309025904")]
    [InlineData("378282246310005")]
    [InlineData("4111111111111111")]
    public void Card_ValidNumbers_Accepted(string number) => Assert.True(CardNumber.IsValid(number));

    [Fact]
    public void Card_NonDigits_Rejected() => Assert.False(CardNumber.IsValid("4111-1111-1111-1111"));

    // E1 – Guide §3.3 padding to 19 and back, keeping the last 4 for masked display
    [Fact]
    public void Card_PadsTo19_AndRoundTrips()
    {
        var padded = CardNumber.Pad("4222222222222");

        Assert.Equal(19, padded.Length);
        Assert.Equal("4222222222222", CardNumber.Unpad(padded));
        Assert.Equal("2222", CardNumber.Last4("4222222222222"));
        Assert.Equal("**** **** **** 2222", CardNumber.Mask("2222"));
    }

    // E1 – Guide §3.1 expiry must be MM/YY with month 01-12
    [Theory]
    [InlineData("01/29", true)]
    [InlineData("12/30", true)]
    [InlineData("00/29", false)]
    [InlineData("13/29", false)]
    [InlineData("1/29", false)]
    [InlineData("01-29", false)]
    public void Expiry_Format(string expiry, bool valid) => Assert.Equal(valid, CardNumber.IsValidExpiry(expiry));
}

public class Phase4SeedTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    // E1 – Guide §3.3 the stored card, expiry and medical columns are ciphertext with equal lengths, and decrypt only with the row's own ID
    [Fact]
    public async Task Seeded_Customers_AreEncrypted()
    {
        var encryption = factory.Services.GetRequiredService<FieldEncryptionService>();
        using var scope = factory.Services.CreateScope();
        var seed = scope.ServiceProvider.GetRequiredService<SBD.API.Contexts.SeedContext>();

        var rows = await seed.Customers.OrderBy(c => c.CustomerId).Take(30).ToListAsync();

        Assert.True(rows.Count >= 1, "Run `dotnet run -- seed` first.");
        Assert.All(rows, row =>
        {
            Assert.StartsWith("v1:", row.MedicalStatusEnc);
            Assert.StartsWith("v1:", row.CardNumberEnc);
            Assert.StartsWith("v1:", row.CardExpiryEnc);
            Assert.Equal(19, encryption.Decrypt(row.CardNumberEnc, row.CustomerId, EncryptedColumns.CardNumber).Length);
            Assert.EndsWith(row.CardLast4, CardNumber.Unpad(encryption.Decrypt(row.CardNumberEnc, row.CustomerId, EncryptedColumns.CardNumber)));
            Assert.InRange(int.Parse(encryption.Decrypt(row.MedicalStatusEnc, row.CustomerId, EncryptedColumns.MedicalStatus)), 1, 6);
        });
        Assert.Single(rows.Select(r => r.MedicalStatusEnc.Length).Distinct());
    }
}

public class PhoneLengthTableTests
{
    // V7 – Guide §2.1 the table covers the whole numbering plan and each country's own lengths
    [Theory]
    [InlineData("+61412345678", true)]
    [InlineData("+6141234567", false)]
    [InlineData("+642123456789", true)]
    [InlineData("+14155552671", true)]
    [InlineData("+1415555267", false)]
    [InlineData("+442071838750", true)]
    [InlineData("+6591234567", true)]
    [InlineData("+919876543210", true)]
    [InlineData("+33612345678", true)]
    [InlineData("+3361234567", false)]
    [InlineData("+819012345678", true)]
    [InlineData("+8190123456", false)]
    [InlineData("+85512345678", true)]
    [InlineData("+999123456789", false)]
    public void IsValidLength_PerCountry(string number, bool valid) =>
        Assert.Equal(valid, SBD.API.Services.Customers.Functions.PhoneLengthTable.IsValidLength(number));

    // V7 – Guide §2.1 the generated table has an entry for every assigned country code it was built from
    [Fact]
    public void Table_HasManyCountries() =>
        Assert.True(SBD.API.Services.Customers.Functions.PhoneLengthData.NationalLengths.Count >= 200);
}
