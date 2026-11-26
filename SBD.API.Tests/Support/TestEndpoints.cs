using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using SBD.API.Contexts;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Auth.Dtos;
using SBD.API.Services.Captcha;
using SBD.API.Services.Seed;
using SBD.API.Models.CustomerDb;
using SBD.API.Common;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore.Diagnostics;
using System.Data.Common;
using Xunit;

namespace SBD.API.Tests.Support;

[ApiController]
[Route("test")]
public class TestController : ControllerBase
{
    [AllowAnonymous, HttpGet("ok")]
    public IActionResult Ping() => Ok();

    [AllowAnonymous, HttpGet("boom")]
    public IActionResult Boom() =>
        throw new InvalidOperationException("SQL failed: Server=db;" + "Pass" + "word=hunter2; SELECT * FROM Customers");

    [AllowAnonymous, HttpPost("login"), EnableRateLimiting("login")]
    public IActionResult Login() => Ok();

    [Authorize("session"), HttpGet("whoami"), HttpPost("whoami")]
    public IActionResult WhoAmI() => Ok(new
    {
        role = User.FindFirstValue(ClaimTypes.Role),
        userId = User.FindFirstValue(ClaimTypes.NameIdentifier),
        permissions = User.FindAll("perm").Select(c => c.Value).ToArray(),
    });

    [Authorize("customer.search"), HttpGet("needs-search")]
    public IActionResult NeedsSearch() => Ok();

    [Authorize("customer.card.reveal"), HttpGet("needs-reveal")]
    public IActionResult NeedsReveal() => Ok();

    [HttpPost("search"), EnableRateLimiting("search")]
    public IActionResult Search() => Ok();
}

public class TestAuthHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "Test";
    public const string UserHeader = "X-Test-User";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var user = Request.Headers[UserHeader].FirstOrDefault();
        if (user is null) return Task.FromResult(AuthenticateResult.NoResult());

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, user)], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(
            new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}

public class ApiWithTestEndpointsFactory : ApiFactory
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            services.AddControllers().AddApplicationPart(typeof(TestController).Assembly);
            services.AddAuthentication(TestAuthHandler.SchemeName)
                .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>(TestAuthHandler.SchemeName, _ => { });
        });
    }
}

public class AuthApiFactory : ApiFactory
{
    public FakeCaptchaVerifier Captcha { get; } = new();
    private readonly List<string> createdUserIds = [];
    private static int nextIp = 1;

    public static string NextIp() => $"127.0.0.{Interlocked.Increment(ref nextIp) % 70 + 2}";

    public async Task<(string UserId, string UserName)> CreateUserAsync(string role, string password = Password)
    {
        using var scope = Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = new ApplicationUser { UserName = "t" + Guid.NewGuid().ToString("N")[..12] };

        Assert.True((await users.CreateAsync(user)).Succeeded);
        Assert.True((await users.AddToRoleAsync(user, role)).Succeeded);
        var result = await users.AddPasswordAsync(user, password);
        Assert.True(result.Succeeded, string.Join("; ", result.Errors.Select(e => e.Description)));

        createdUserIds.Add(user.Id);
        return (user.Id, user.UserName);
    }

    public void TrackUser(string userId) => createdUserIds.Add(userId);

    public async Task<T> WithDbAsync<T>(Func<AuthDbContext, UserManager<ApplicationUser>, Task<T>> action)
    {
        using var scope = Services.CreateScope();
        return await action(
            scope.ServiceProvider.GetRequiredService<AuthDbContext>(),
            scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>());
    }

    public CommandCounter CustomerCommands { get; } = new();

    public const string Password = "correct-horse-battery-staple";
    private readonly List<int> createdCustomerIds = [];

    public static string UniqueLetters(int length) =>
        new(Enumerable.Range(0, length).Select(_ => (char)('a' + Random.Shared.Next(26))).ToArray());

    public async Task<(int Id, NewCustomer Data)> CreateCustomerAsync(
        string lastName, string firstName = "Test", string phone = "+61412345678",
        string card = "4111111111111111", MedicalStatus status = MedicalStatus.Covid)
    {
        using var scope = Services.CreateScope();
        var localityId = await scope.ServiceProvider.GetRequiredService<SeedContext>().Localities
            .Where(l => l.Suburb == "Richmond" && l.State == "VIC").Select(l => l.LocalityId).SingleAsync();
        var data = new NewCustomer(firstName, lastName, null, "1 Test Street", localityId, phone, status, card, "12/30");
        var ids = await scope.ServiceProvider.GetRequiredService<CustomerSeeder>().AddAsync([data]);
        createdCustomerIds.AddRange(ids);
        return (ids[0], data);
    }

    public async Task CreateManyCustomersAsync(string lastName, int count)
    {
        using var scope = Services.CreateScope();
        var localityId = await scope.ServiceProvider.GetRequiredService<SeedContext>().Localities
            .Where(l => l.Suburb == "Richmond" && l.State == "VIC").Select(l => l.LocalityId).SingleAsync();
        var batch = Enumerable.Range(0, count)
            .Select(i => new NewCustomer("Bulk", lastName, null, "1 Test Street", localityId, "+61412345678", MedicalStatus.Healthy, "4111111111111111", "12/30"))
            .ToList();
        createdCustomerIds.AddRange(await scope.ServiceProvider.GetRequiredService<CustomerSeeder>().AddAsync(batch));
    }

    public async Task<TResult> WithServiceAsync<TService, TResult>(Func<TService, Task<TResult>> action) where TService : notnull
    {
        using var scope = Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<TService>());
    }

    public async Task<(HttpClient Client, string UserId, string UserName)> SignInAsync(string role)
    {
        var (userId, userName) = await CreateUserAsync(role);
        var needsMfa = RoleNames.RequiringMfa.Contains(role);
        string? key = null;
        if (needsMfa)
        {
            key = await WithDbAsync(async (db, users) =>
            {
                var user = (await users.FindByIdAsync(userId))!;
                await users.ResetAuthenticatorKeyAsync(user);
                await users.SetTwoFactorEnabledAsync(user, true);
                return (await users.GetAuthenticatorKeyAsync(user))!;
            });
        }

        var client = CreateApiClient(remoteIp: NextIp());
        var login = (await (await client.PostAsJsonAsync("/auth/login", new LoginRequest(userName, Password, null))).Content.ReadFromJsonAsync<LoginResponse>())!;
        if (needsMfa)
            login = (await (await client.PostAsJsonAsync("/auth/mfa", new MfaCodeRequest(login.MfaTicket, Totp.Code(key!)))).Content.ReadFromJsonAsync<LoginResponse>())!;

        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", login.Token);
        return (client, userId, userName);
    }

    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.ConfigureServices(services =>
        {
            services.AddControllers().AddApplicationPart(typeof(TestController).Assembly);
            services.AddSingleton<Microsoft.EntityFrameworkCore.Diagnostics.IInterceptor>(CustomerCommands);
            services.RemoveAll<ICaptchaVerifier>();
            services.AddSingleton<ICaptchaVerifier>(Captcha);
        });
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && createdCustomerIds.Count > 0)
        {
            using var customers = new SeedContext(new DbContextOptionsBuilder<SeedContext>()
                .UseSqlServer(Environment.GetEnvironmentVariable("ConnectionStrings__CustomerSeed")).Options);
            customers.Customers.Where(c => createdCustomerIds.Contains(c.CustomerId)).ExecuteDelete();
        }
        if (disposing && createdUserIds.Count > 0)
        {
            using var db = new AuthDbContext(new DbContextOptionsBuilder<AuthDbContext>()
                .UseSqlServer(Environment.GetEnvironmentVariable("ConnectionStrings__Auth")).Options);
            db.Users.Where(u => createdUserIds.Contains(u.Id)).ExecuteDelete();
        }
        base.Dispose(disposing);
    }
}

public class FakeCaptchaVerifier : ICaptchaVerifier
{
    public bool Result { get; set; } = true;
    public int Calls { get; private set; }

    public Task<bool> VerifyAsync(string token, string? clientIp)
    {
        Calls++;
        return Task.FromResult(Result);
    }
}

public class CommandCounter : DbCommandInterceptor
{
    private int count;
    public int Count => count;

    public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(
        DbCommand command, CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
    {
        if (command.CommandText.Contains("vw_") || command.CommandText.Contains("[Customers]")) Interlocked.Increment(ref count);
        return base.ReaderExecutingAsync(command, eventData, result, cancellationToken);
    }
}
