using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Models.AuthDb;
using SBD.API.Models.CustomerDb;
using SBD.API.Services.Customers;
using SBD.API.Services.Customers.Functions;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase4SearchTests(AuthApiFactory factory) : IClassFixture<AuthApiFactory>
{
    private static Task<HttpResponseMessage> SearchAsync(HttpClient client, object body) => client.PostAsJsonAsync("/customers/search", body);

    private static async Task<string[]> PropertyNamesAsync(HttpResponseMessage response)
    {
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return [.. json.RootElement[0].EnumerateObject().Select(p => p.Name).Order()];
    }

    private async Task<(HttpClient Client, string UserId)> NormalAsync()
    {
        var (client, userId, _) = await factory.SignInAsync(RoleNames.Normal);
        return (client, userId);
    }

    // ---------- input validation (V2, V3, V4, V5, V6, V7) ----------

    // V2 – Guide §2.1 a 50-character last name is accepted
    [Fact]
    public async Task LastName_50Chars_Accepted()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = new string('a', 50) })).StatusCode);
    }

    // V2 – Guide §2.1 a 51-character last name is rejected
    [Fact]
    public async Task LastName_51Chars_Rejected()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { lastName = new string('a', 51) })).StatusCode);
    }

    // V3 – Guide §2.1 script, punctuation and a leading digit are rejected, not cleaned up
    [Theory]
    [InlineData("<script>")]
    [InlineData("Smith;")]
    [InlineData("1Smith")]
    public async Task Name_DisallowedChars_Rejected(string name)
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { lastName = name })).StatusCode);
    }

    // V3 – Guide §2.1 apostrophes, accents and hyphens are accepted
    [Theory]
    [InlineData("O'Brien")]
    [InlineData("Zoë")]
    [InlineData("Mary-Jane")]
    public async Task Name_Apostrophe_And_Accent_Accepted(string name)
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = name })).StatusCode);
    }

    // V3 – Guide §2.1 an accent typed as e + combining mark is normalised to the stored single character and finds the customer
    [Fact]
    public async Task Normalisation_NFC_FindsAccentedName()
    {
        var lastName = "Zoë" + AuthApiFactory.UniqueLetters(6);
        await factory.CreateCustomerAsync(lastName);
        var (client, _) = await NormalAsync();

        var decomposed = lastName.Normalize(System.Text.NormalizationForm.FormD);
        var response = await SearchAsync(client, new { lastName = decomposed });

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(1, json.RootElement.GetArrayLength());
    }

    // V2 – Guide §2.1 a postcode must be exactly four digits
    [Theory]
    [InlineData("312")]
    [InlineData("31210")]
    [InlineData("abcd")]
    public async Task Postcode_NotFourDigits_Rejected(string postcode)
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { lastName = "Smith", postcode })).StatusCode);
    }

    // V6 – Guide §2.1 a suburb, state and postcode that do not belong together are rejected; the real combination is accepted
    [Fact]
    public async Task InvalidLocality_Rejected()
    {
        var (client, _) = await NormalAsync();

        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { lastName = "Smith", suburb = "Richmond", state = "QLD", postcode = "3121" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = "Smith", suburb = "Richmond", state = "VIC", postcode = "3121" })).StatusCode);
    }

    // V4 – Guide §2.2 one * at the end after at least 3 characters
    [Theory]
    [InlineData("*", false)]
    [InlineData("Sm*", false)]
    [InlineData("S*m", false)]
    [InlineData("**", false)]
    [InlineData("Smi**", false)]
    [InlineData("Smi*", true)]
    public async Task Wildcard_Rules_Enforced(string lastName, bool accepted)
    {
        var (client, _) = await NormalAsync();
        var expected = accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest;
        Assert.Equal(expected, (await SearchAsync(client, new { lastName })).StatusCode);
    }

    // V5 – Guide §2.2 an address-only search is refused
    [Fact]
    public async Task AddressOnlySearch_Rejected()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { suburb = "Richmond", state = "VIC", postcode = "3121" })).StatusCode);
    }

    // V7 – Guide §2.1 a phone number whose length does not fit its country code is rejected
    [Theory]
    [InlineData("+6141234567", false)]
    [InlineData("+614123456789", false)]
    [InlineData("+61412345678", true)]
    [InlineData("+999123456789", false)]
    [InlineData("0412345678", false)]
    public async Task Phone_WrongLengthForCountry_Rejected(string phone, bool accepted)
    {
        var (client, _) = await NormalAsync();
        var expected = accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest;
        Assert.Equal(expected, (await SearchAsync(client, new { phone })).StatusCode);
    }

    // V4 – Guide §2.2 a phone wildcard needs at least 3 digits, so a country code alone is refused
    [Theory]
    [InlineData("+61*", false)]
    [InlineData("+6*", false)]
    [InlineData("+614*", true)]
    [InlineData("+61412*", true)]
    public async Task PhoneWildcard_NeedsThreeDigits(string phone, bool accepted)
    {
        var (client, _) = await NormalAsync();
        var expected = accepted ? HttpStatusCode.OK : HttpStatusCode.BadRequest;
        Assert.Equal(expected, (await SearchAsync(client, new { phone })).StatusCode);
    }

    // E3 – Guide §2.2 page, skip and offset (or any unknown field) are refused
    [Theory]
    [InlineData("page")]
    [InlineData("skip")]
    [InlineData("offset")]
    public async Task Paging_Refused(string field)
    {
        var (client, _) = await NormalAsync();
        var body = new Dictionary<string, object> { ["lastName"] = "Smith", [field] = 1 };
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, body)).StatusCode);
    }

    // ---------- SQL injection (V1) ----------

    // V1 – Guide §3.2 a classic injection string in the last name is rejected by the validator
    [Fact]
    public async Task Injection_InLastName_Rejected()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { lastName = "' OR '1'='1" })).StatusCode);
    }

    // V1 – Guide §3.2 a classic injection string in the phone is rejected by the validator
    [Fact]
    public async Task Injection_InPhone_Rejected()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.BadRequest, (await SearchAsync(client, new { phone = "' OR '1'='1" })).StatusCode);
    }

    // V1 – Guide §3.2 even if the validator were bypassed, the parameterised query returns no rows, not every row
    [Fact]
    public async Task Injection_AtQueryLayer_ReturnsNoRows()
    {
        await factory.CreateCustomerAsync("Injectable" + AuthApiFactory.UniqueLetters(4));
        var (_, userId) = await NormalAsync();

        var outcome = await factory.WithServiceAsync<CustomerSearchService, SearchOutcome>(service =>
            service.SearchAsync(userId, CustomerAccess.NormalConnection,
                new SearchCriteria(null, new SearchTerm("' OR '1'='1", false), null, null, null, null, null, null)));

        Assert.Empty(outcome.Results!);
    }

    // V1 – Guide §2.2 % and _ typed into a prefix are matched literally and do not widen the search
    [Fact]
    public async Task Wildcard_PercentAndUnderscore_AreLiteral()
    {
        await factory.CreateCustomerAsync("Literal" + AuthApiFactory.UniqueLetters(4));
        var (_, userId) = await NormalAsync();

        foreach (var prefix in new[] { "%", "_", "[a-z]", "Lit_ral" })
        {
            var outcome = await factory.WithServiceAsync<CustomerSearchService, SearchOutcome>(service =>
                service.SearchAsync(userId, CustomerAccess.NormalConnection,
                    new SearchCriteria(null, new SearchTerm(prefix, true), null, null, null, null, null, null)));
            Assert.Empty(outcome.Results!);
        }
    }

    // E3 – Guide §2.2 never more than 50 rows
    [Fact]
    public async Task ResultCap_50()
    {
        var lastName = "Cap" + AuthApiFactory.UniqueLetters(8);
        await factory.CreateManyCustomersAsync(lastName, 60);
        var (client, _) = await NormalAsync();

        var response = await SearchAsync(client, new { lastName });

        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(50, json.RootElement.GetArrayLength());
    }

    // ---------- one DTO per role (R1) ----------

    private static readonly string[] NormalFields = ["firstName", "id", "lastName", "phone", "postcode", "state", "street", "suburb", "unit"];

    // R1 – Guide §4.1, §4.3 a Normal user gets no card or medical fields
    [Fact]
    public async Task Normal_SeesNoCardOrMedical()
    {
        var lastName = "Role" + AuthApiFactory.UniqueLetters(8);
        await factory.CreateCustomerAsync(lastName);
        var (client, _) = await NormalAsync();

        var response = await SearchAsync(client, new { lastName });

        Assert.Equal(NormalFields, await PropertyNamesAsync(response));
    }

    // R1 – Guide §4.1, §4.3 Accounting gets the masked card and nothing else extra
    [Fact]
    public async Task Accounting_SeesMaskedCard_NoMedical()
    {
        var lastName = "Role" + AuthApiFactory.UniqueLetters(8);
        await factory.CreateCustomerAsync(lastName);
        var (client, _, _) = await factory.SignInAsync(RoleNames.Accounting);

        var response = await SearchAsync(client, new { lastName });
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(NormalFields.Append("cardMasked").Order().ToArray(), await PropertyNamesAsync(new HttpResponseMessage { Content = new StringContent(body) }));
        Assert.Contains("**** **** **** 1111", body);
        Assert.DoesNotContain("4111111111111111", body);
        Assert.DoesNotContain("Covid", body);
    }

    // R1 – Guide §4.1, §4.3 Privileged gets every field, decrypted
    [Fact]
    public async Task Privileged_SeesAllFields()
    {
        var lastName = "Role" + AuthApiFactory.UniqueLetters(8);
        await factory.CreateCustomerAsync(lastName);
        var (client, _, _) = await factory.SignInAsync(RoleNames.Privileged);

        var response = await SearchAsync(client, new { lastName });
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(
            NormalFields.Concat(["cardExpiry", "cardMasked", "cardNumber", "medicalStatus"]).Order().ToArray(),
            await PropertyNamesAsync(new HttpResponseMessage { Content = new StringContent(body) }));
        Assert.Contains("\"cardNumber\":\"4111111111111111\"", body);
        Assert.Contains("\"medicalStatus\":\"Covid\"", body);
        Assert.Contains("\"cardExpiry\":\"12/30\"", body);
    }

    // R1 – Guide §5 every customer whose medical status is returned is audited as MedicalViewed
    [Fact]
    public async Task Privileged_Search_AuditsMedicalViewed()
    {
        var lastName = "Audit" + AuthApiFactory.UniqueLetters(8);
        var (firstId, _) = await factory.CreateCustomerAsync(lastName);
        var (secondId, _) = await factory.CreateCustomerAsync(lastName);
        var (client, userId, _) = await factory.SignInAsync(RoleNames.Privileged);

        await SearchAsync(client, new { lastName });

        var audited = await factory.WithDbAsync((db, _) => db.AuditLogs
            .Where(a => a.ActorUserId == userId && a.Action == AuditAction.MedicalViewed).Select(a => a.TargetCustomerId).ToListAsync());
        Assert.Equal(new[] { firstId, secondId }.Order(), audited.Select(id => id!.Value).Order());
    }

    // R6 – Guide §4.4 a User Admin cannot search customer data
    [Fact]
    public async Task Admin_CannotSearch()
    {
        var (client, _, _) = await factory.SignInAsync(RoleNames.UserAdmin);
        Assert.Equal(HttpStatusCode.Forbidden, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);
    }

    // ---------- card reveal (R5) ----------

    // R5 – Guide §3.3, §4.4 a Normal user cannot reveal a card
    [Fact]
    public async Task Reveal_Normal_Forbidden()
    {
        var (id, _) = await factory.CreateCustomerAsync("Reveal" + AuthApiFactory.UniqueLetters(6));
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.Forbidden, (await client.PostAsync($"/customers/{id}/card/reveal", null)).StatusCode);
    }

    // R5 – Guide §3.3, §4.4 Accounting can reveal; the audit row names the customer and holds no card number
    [Fact]
    public async Task Reveal_Accounting_Logged()
    {
        var (id, _) = await factory.CreateCustomerAsync("Reveal" + AuthApiFactory.UniqueLetters(6), card: "5555555555554444");
        var (client, userId, _) = await factory.SignInAsync(RoleNames.Accounting);

        var response = await client.PostAsync($"/customers/{id}/card/reveal", null);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("5555555555554444", body);
        Assert.Contains("12/30", body);

        var audit = await factory.WithDbAsync((db, _) => db.AuditLogs
            .SingleAsync(a => a.ActorUserId == userId && a.Action == AuditAction.CardRevealed));
        Assert.Equal(id, audit.TargetCustomerId);
        Assert.Equal(AuditOutcome.Success, audit.Outcome);
    }

    // R5 – Guide §4.4 the 21st reveal in a day is refused and raises an alert
    [Fact]
    public async Task Reveal_21st_Blocked()
    {
        var (id, _) = await factory.CreateCustomerAsync("Reveal" + AuthApiFactory.UniqueLetters(6));
        var (client, userId, _) = await factory.SignInAsync(RoleNames.Accounting);

        for (var attempt = 1; attempt <= 20; attempt++)
            Assert.Equal(HttpStatusCode.OK, (await client.PostAsync($"/customers/{id}/card/reveal", null)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsync($"/customers/{id}/card/reveal", null)).StatusCode);
        Assert.Equal(1, await factory.WithDbAsync((db, _) =>
            db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.CardRevealLimit)));
    }

    // R5 – Guide §3.3 revealing a customer that does not exist returns 404
    [Fact]
    public async Task Reveal_UnknownCustomer_404()
    {
        var (client, _, _) = await factory.SignInAsync(RoleNames.Accounting);
        Assert.Equal(HttpStatusCode.NotFound, (await client.PostAsync("/customers/2000000000/card/reveal", null)).StatusCode);
    }

    // ---------- daily quotas and anti-harvesting (E3, E4, E5) ----------

    private Task AddSearchLogsAsync(string userId, int count, short resultCount = 1, bool wildcard = false, bool distinctFingerprints = false) =>
        factory.WithDbAsync(async (db, _) =>
        {
            db.SearchLogs.AddRange(Enumerable.Range(0, count).Select(i => new SearchLog
            {
                UserId = userId,
                OccurredUtc = DateTime.UtcNow.AddSeconds(-1),
                UsedWildcard = wildcard,
                PrefixLength = 3,
                PrefixFingerprint = wildcard && distinctFingerprints ? System.Security.Cryptography.SHA256.HashData(BitConverter.GetBytes(i + 1000)) : null,
                ResultCount = resultCount,
            }));
            await db.SaveChangesAsync();
            return 0;
        });

    // E3 – Guide §2.2 at 300 searches a day the user's search is paused and an alert is raised
    [Fact]
    public async Task DailyHardLimit_Pauses()
    {
        var (client, userId) = await NormalAsync();
        await AddSearchLogsAsync(userId, 300);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);

        var state = await factory.WithDbAsync(async (db, _) => (
            paused: await db.Users.Where(u => u.Id == userId).Select(u => u.SearchPausedUntilUtc).SingleAsync(),
            alerts: await db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.SearchHardLimit)));
        Assert.True(state.paused > DateTime.UtcNow.AddYears(1));
        Assert.Equal(1, state.alerts);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);
    }

    // E3 – Guide §2.2 2,000 returned records a day also pauses the search
    [Fact]
    public async Task DailyRecordLimit_Pauses()
    {
        var (client, userId) = await NormalAsync();
        await AddSearchLogsAsync(userId, 40, resultCount: 50);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);
    }

    // E3 – Guide §2.2 at 50% a soft-limit alert is raised once and searching continues
    [Fact]
    public async Task SoftLimit_RaisesAlert()
    {
        var (client, userId) = await NormalAsync();
        await AddSearchLogsAsync(userId, 150);

        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);

        Assert.Equal(1, await factory.WithDbAsync((db, _) =>
            db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.SearchSoftLimit)));
    }

    // E3 – Guide §2.2, §6 after a User Admin unlock the user can search again, with a fresh count
    [Fact]
    public async Task Unlock_ResumesSearch()
    {
        var (client, userId) = await NormalAsync();
        await AddSearchLogsAsync(userId, 300);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);

        await factory.WithDbAsync(async (db, _) =>
        {
            await db.Users.Where(u => u.Id == userId).ExecuteUpdateAsync(u => u.SetProperty(x => x.SearchPausedUntilUtc, (DateTime?)null));
            db.AuditLogs.Add(new AuditLog
            {
                OccurredUtc = DateTime.UtcNow, ActorUserId = "admin-for-test", Action = AuditAction.SearchUnlocked,
                Outcome = AuditOutcome.Success, TargetUserId = userId,
            });
            await db.SaveChangesAsync();
            return 0;
        });

        Assert.Equal(HttpStatusCode.OK, (await SearchAsync(client, new { lastName = "Smith" })).StatusCode);
    }

    // E5 – Guide §5, §6 the search log holds a fingerprint and counts, never the typed name
    [Fact]
    public async Task SearchLog_ContainsNoNames()
    {
        var (client, userId) = await NormalAsync();
        var prefix = "Secret" + AuthApiFactory.UniqueLetters(5);

        await SearchAsync(client, new { lastName = prefix + "*" });

        var row = await factory.WithDbAsync((db, _) => db.SearchLogs.SingleAsync(s => s.UserId == userId));
        Assert.True(row.UsedWildcard);
        Assert.Equal(prefix.Length, row.PrefixLength);
        Assert.Equal(32, row.PrefixFingerprint!.Length);
        var keyed = factory.Services.GetRequiredService<SearchFingerprint>().Compute(prefix);
        Assert.True(keyed.SequenceEqual(row.PrefixFingerprint));
        Assert.False(System.Text.Encoding.UTF8.GetBytes(prefix.ToLowerInvariant()).SequenceEqual(row.PrefixFingerprint));
        Assert.False(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(prefix.ToLowerInvariant())).SequenceEqual(row.PrefixFingerprint));
        Assert.Equal(["UserId"], typeof(SearchLog).GetProperties().Where(p => p.PropertyType == typeof(string)).Select(p => p.Name));
    }

    // E4 – Guide §6 15 wildcard searches with different fingerprints within 10 minutes raise an alphabet-walk alert
    [Fact]
    public async Task AlphabetWalk_RaisesAlert()
    {
        var (client, userId) = await NormalAsync();
        await AddSearchLogsAsync(userId, 14, wildcard: true, distinctFingerprints: true);
        Assert.Equal(0, await factory.WithDbAsync((db, _) => db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.AlphabetWalk)));

        await SearchAsync(client, new { lastName = "Abc*" });

        Assert.Equal(1, await factory.WithDbAsync((db, _) =>
            db.SecurityAlerts.CountAsync(a => a.UserId == userId && a.AlertType == SecurityAlertType.AlphabetWalk)));
    }

    // A11 – Guide §3.2 an anonymous search gets 401 and no customer query reaches the database
    [Fact]
    public async Task Anonymous_Search_401_NoCustomerQuery()
    {
        var before = factory.CustomerCommands.Count;

        var response = await SearchAsync(factory.CreateApiClient(remoteIp: AuthApiFactory.NextIp()), new { lastName = "Smith" });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal(before, factory.CustomerCommands.Count);
    }

    // E8 – Guide §2.3 search is POST only, so personal data cannot be sent in a URL
    [Fact]
    public async Task Search_OverGet_NotAllowed()
    {
        var (client, _) = await NormalAsync();
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await client.GetAsync("/customers/search?lastName=Smith")).StatusCode);
    }

    // R4 – Guide §3.2, §4.3 a view login cannot even open AuthDb (report B9)
    [Fact]
    public async Task ViewLogin_CannotOpenAuthDb()
    {
        var connection = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(
            Environment.GetEnvironmentVariable("ConnectionStrings__CustomerNormal")) { InitialCatalog = "AuthDb" };

        await using var sql = new Microsoft.Data.SqlClient.SqlConnection(connection.ConnectionString);

        await Assert.ThrowsAsync<Microsoft.Data.SqlClient.SqlException>(() => sql.OpenAsync());
    }

    // ---------- localities (V6) ----------

    // V6 – Guide §2.1 the locality list for a state feeds the dropdowns
    [Fact]
    public async Task Localities_ByState_ReturnsList()
    {
        var (client, _) = await NormalAsync();

        var response = await client.GetAsync("/localities?state=VIC");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("\"suburb\":\"Richmond\"", body);
        Assert.Contains("\"postcode\":\"3121\"", body);
        Assert.DoesNotContain("\"state\":\"NSW\"", body);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.GetAsync("/localities?state=XX")).StatusCode);
    }
}
