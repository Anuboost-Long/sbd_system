/*
 * File: CustomerSeeder.cs
 * Implements: Guide §3.3 encrypted customer rows are written with the row ID bound into the encryption.
 * Controls:   E1
 */
using Microsoft.EntityFrameworkCore;
using SBD.API.Contexts;
using SBD.API.Models.CustomerDb;
using SBD.API.Services.Customers.Functions;
using SBD.API.Services.Encryption;

namespace SBD.API.Services.Seed;

public record NewCustomer(
    string FirstName,
    string LastName,
    string? Unit,
    string Street,
    int LocalityId,
    string Phone,
    MedicalStatus MedicalStatus,
    string CardNumber,
    string CardExpiry);

public class CustomerSeeder(SeedContext seed, FieldEncryptionService encryption)
{
    // [Guide §3.3] Insert each customer with placeholder ciphertext, read its new ID, then store the real ciphertext, all in one transaction.
    // Why: the customer ID is part of the encryption (associated data), but the database only assigns it on insert; the transaction means
    // no row is ever left holding a placeholder.
    // Standard: OWASP ASVS 5.0 V11.3.2; PCI DSS v4.0.1 Req 3.5.1.
    // Evidence: test Seeded_Customers_AreEncrypted (E1).
    public async Task<IReadOnlyList<int>> AddAsync(IReadOnlyCollection<NewCustomer> newCustomers)
    {
        foreach (var customer in newCustomers)
        {
            if (!CardNumber.IsValid(customer.CardNumber)) throw new ArgumentException("Card number fails the length or Luhn check.");
            if (!CardNumber.IsValidExpiry(customer.CardExpiry)) throw new ArgumentException("Card expiry must be MM/YY.");
        }

        // [Guide §3.2] parameterised (EF inserts)
        await using var transaction = await seed.Database.BeginTransactionAsync();

        var rows = newCustomers.Select(c => new Customer
        {
            FirstName = InputNormaliser.Normalise(c.FirstName)!,
            LastName = InputNormaliser.Normalise(c.LastName)!,
            Unit = InputNormaliser.Normalise(c.Unit),
            Street = InputNormaliser.Normalise(c.Street)!,
            LocalityId = c.LocalityId,
            Phone = c.Phone,
            MedicalStatusEnc = "v0:pending",
            CardNumberEnc = "v0:pending",
            CardLast4 = CardNumber.Last4(c.CardNumber),
            CardExpiryEnc = "v0:pending",
        }).ToList();
        seed.Customers.AddRange(rows);
        await seed.SaveChangesAsync();

        foreach (var (row, source) in rows.Zip(newCustomers))
        {
            // [Guide §3.1] Medical status is stored as a one-digit code (1-6), so every encrypted value has the same length.
            // Why: equal length hides which status is stored.
            // Standard: OWASP ASVS 5.0 V11.3.2; Guide §3.1.
            // Evidence: test MedicalStatus_AllCodes_SameCiphertextLength (E1).
            row.MedicalStatusEnc = encryption.Encrypt(((byte)source.MedicalStatus).ToString(), row.CustomerId, EncryptedColumns.MedicalStatus);
            row.CardNumberEnc = encryption.Encrypt(CardNumber.Pad(source.CardNumber), row.CustomerId, EncryptedColumns.CardNumber);
            row.CardExpiryEnc = encryption.Encrypt(source.CardExpiry, row.CustomerId, EncryptedColumns.CardExpiry);
        }
        await seed.SaveChangesAsync();
        await transaction.CommitAsync();

        return [.. rows.Select(r => r.CustomerId)];
    }
}
