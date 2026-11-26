/*
 * File: SeedService.cs
 * Implements: Guide §3.1 synthetic demo users and customers only.
 * Controls:   E1
 */
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Models.CustomerDb;

namespace SBD.API.Services.Seed;

public class SeedService(
    UserManager<ApplicationUser> users,
    SeedContext seed,
    CustomerSeeder customerSeeder,
    IConfiguration configuration,
    ILogger<SeedService> logger)
{
    private static readonly (string UserName, string Role, string PasswordSetting)[] DemoUsers =
    [
        ("normal.user", RoleNames.Normal, "SEED_NORMAL_PASSWORD"),
        ("accounting.user", RoleNames.Accounting, "SEED_ACCOUNTING_PASSWORD"),
        ("privileged.user", RoleNames.Privileged, "SEED_PRIVILEGED_PASSWORD"),
        ("user.admin", RoleNames.UserAdmin, "SEED_USERADMIN_PASSWORD"),
    ];

    // [Guide §3.1] Only invented people and standard card test numbers are used; no real personal data is ever loaded.
    // Why: the demo must be safe to share and to attach to the submission.
    // Standard: PCI DSS v4.0.1 Req 3.4.1.
    // Evidence: test Seeded_Customers_AreEncrypted (E1).
    private static readonly string[] FirstNames = ["Olivia", "Liam", "Zoë", "Noah", "Mary-Jane", "Jack", "Ava", "Ethan", "Mia", "Lucas"];
    private static readonly string[] LastNames = ["Smith", "O'Brien", "Nguyen", "Patel", "Brown", "Wilson", "Taylor", "Anderson", "Thomas", "White"];
    private static readonly string[] Streets = ["12 Collins Street", "5 George Street", "88 Queen Street", "3 Hay Street", "21 King William Street"];
    private static readonly string[] Phones = ["+61412345678", "+61498765432", "+6421234567", "+14155552671", "+442071838750", "+6591234567", "+919876543210"];
    private static readonly string[] TestCards =
    [
        "4111111111111111", "4012888888881881", "5555555555554444", "5105105105105100", "378282246310005",
        "371449635398431", "6011111111111117", "30569309025904", "3530111333300000", "4222222222222",
    ];

    public async Task RunAsync()
    {
        foreach (var (userName, role, passwordSetting) in DemoUsers)
        {
            if (await users.FindByNameAsync(userName) is not null) continue;

            var password = configuration[passwordSetting]
                ?? throw new InvalidOperationException($"{passwordSetting} is not set in .env.");
            var user = new ApplicationUser { UserName = userName };
            Require(await users.CreateAsync(user), userName);
            Require(await users.AddToRoleAsync(user, role), userName);
            Require(await users.AddPasswordAsync(user, password), userName);
            logger.LogInformation("Seeded user {UserName} with role {Role}", userName, role);
        }

        // [Guide §3.2] parameterised
        if (await seed.Customers.AnyAsync())
        {
            logger.LogInformation("Customers already exist; skipping customer seed");
            return;
        }

        // [Guide §3.2] parameterised
        var localityIds = await seed.Localities.Select(l => l.LocalityId).ToListAsync();
        var random = new Random(2026);
        var customers = Enumerable.Range(0, 30).Select(i => new NewCustomer(
            FirstNames[i % FirstNames.Length],
            LastNames[random.Next(LastNames.Length)],
            i % 4 == 0 ? $"{i + 1}" : null,
            Streets[random.Next(Streets.Length)],
            localityIds[random.Next(localityIds.Count)],
            Phones[random.Next(Phones.Length)],
            (MedicalStatus)random.Next(1, 7),
            TestCards[i % TestCards.Length],
            $"{random.Next(1, 13):D2}/{random.Next(28, 33)}")).ToList();

        await customerSeeder.AddAsync(customers);
        logger.LogInformation("Seeded {Count} synthetic customers", customers.Count);
    }

    private static void Require(IdentityResult result, string userName)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException($"Could not create {userName}: {string.Join("; ", result.Errors.Select(e => e.Description))}");
    }
}
