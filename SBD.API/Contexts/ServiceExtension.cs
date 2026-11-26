/*
 * File: ServiceExtension.cs
 * Implements: Guide §2.4, §2.5, §4.1, §4.3 password hashing, lockout, session authentication and permission policies.
 * Controls:   A1, A2, A3, A6, R3
 */
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SBD.API.Common;
using SBD.API.Middleware;
using SBD.API.Models.AuthDb;
using SBD.API.Services.Admin;
using SBD.API.Services.Audit;
using SBD.API.Services.Auth;
using SBD.API.Services.Auth.Functions;
using SBD.API.Services.Captcha;
using SBD.API.Services.Customers;
using SBD.API.Services.Customers.Functions;
using SBD.API.Services.Encryption;
using SBD.API.Services.Seed;
using SBD.API.Services.Session;
using SBD.API.SetUp;

namespace SBD.API.Contexts;

public static class ServiceExtension
{
    // [Guide §2.3, §3.2] DEPLOYMENT ITEM, not active in this demo:
    // in production the database connection uses a CA-signed certificate with TLS 1.3 enforced on SQL Server.
    // Demo trusts the Docker self-signed certificate (TrustServerCertificate=True) on localhost only.
    public static IServiceCollection AddDatabaseContexts(this IServiceCollection services, IConfiguration configuration, bool logSql)
    {
        void Configure(DbContextOptionsBuilder options, string connectionName)
        {
            options.UseSqlServer(configuration.GetConnectionString(connectionName));

            // [Guide §3.2] In development the generated SQL is written to the console so the @p0 parameters are visible as evidence;
            // sensitive-data logging stays off, so parameter values are never printed.
            // Why: shows the marker that values travel separately from the command text (parameterised query).
            // Standard: OWASP ASVS 5.0 V1.2.4.
            // Evidence: console output of test Injection_AtQueryLayer_ReturnsNoRows (V1).
            options.EnableSensitiveDataLogging(false);
            if (logSql) options.LogTo(Console.WriteLine, [RelationalEventId.CommandExecuted], LogLevel.Information);
        }

        services.AddDbContext<AuthDbContext>(options => Configure(options, "Auth"));
        services.AddDbContext<NormalViewContext>(options => Configure(options, "CustomerNormal"));
        services.AddDbContext<AccountingViewContext>(options => Configure(options, "CustomerAccounting"));
        services.AddDbContext<PrivilegedViewContext>(options => Configure(options, "CustomerPrivileged"));
        services.AddDbContext<SeedContext>(options => Configure(options, "CustomerSeed"));
        return services;
    }

    public static IServiceCollection AddIdentitySetup(this IServiceCollection services)
    {
        // [Guide §2.4] Hash passwords with PBKDF2-HMAC-SHA512 at 600,000 iterations and a salt per user (the Identity default is 100,000).
        // Why: a slow salted hash makes stolen hashes costly to crack; PBKDF2 was chosen over Argon2id to avoid an extra dependency.
        // Standard: OWASP ASVS 5.0 V11.4.2; OWASP Password Storage Cheat Sheet.
        // Evidence: tests Password_IsStoredAsHash_NotPlainText, Hasher_Uses600kIterations (A1, A2).
        services.Configure<PasswordHasherOptions>(options => options.IterationCount = 600_000);

        // [Guide §2.4, §2.5] Lock an account for 15 minutes after 5 failed logins, and set no password composition rules; length is checked by PasswordPolicyValidator.
        // Why: lockout is the main brake on guessing; length beats complexity rules.
        // Standard: OWASP ASVS 5.0 V6.3.1, V6.1.1, V6.2.5; NIST SP 800-63B-4.
        // Evidence: tests SixthAttempt_AccountLocked, Password_NoCompositionRules (A3, A6).
        services.AddIdentityCore<ApplicationUser>(options =>
            {
                options.Lockout.AllowedForNewUsers = true;
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                options.Password.RequiredLength = 8;
                options.Password.RequiredUniqueChars = 1;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._";
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<AuthDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders()
            .AddPasswordValidator<PasswordPolicyValidator>()
            .AddPasswordValidator<BreachedPasswordValidator>()
            .AddUserValidator<UsernameLengthValidator>();

        services.AddSingleton<BreachedPasswordList>();
        return services;
    }

    public static IServiceCollection AddSecurityServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<SecurityOptions>()
            .Bind(configuration.GetSection("Security"))
            .Validate(o => o.ApiKey.Length > 0 && SecurityOptions.ParseIps(o.AllowedIps).Count > 0 && SecurityOptions.ParseIps(o.AdminAllowedIps).Count > 0,
                "Security__ApiKey, Security__AllowedIps and Security__AdminAllowedIps must be set.")
            .ValidateOnStart();

        services.AddExceptionHandler<GlobalExceptionHandler>();
        services.AddProblemDetails();
        services.AddSecurityRateLimiter();

        services.AddHttpContextAccessor();
        services.AddScoped<IAuditLogger, AuditLogger>();
        return services;
    }

    public static IServiceCollection AddAuthenticationServices(this IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton<LoginFailureTracker>();
        services.AddSingleton<MfaTicketStore>();
        services.AddSingleton<DummyPasswordHash>();
        services.AddHttpClient<ICaptchaVerifier, TurnstileVerifier>(client => client.Timeout = TimeSpan.FromSeconds(5));
        services.AddScoped<ISessionService, SessionService>();
        services.AddScoped<AuthService>();
        services.AddScoped<AdminService>();
        services.AddScoped<InactiveAccountService>();
        services.AddHostedService<InactiveAccountJob>();

        services.AddAuthentication(SessionAuthenticationHandler.SchemeName)
            .AddScheme<AuthenticationSchemeOptions, SessionAuthenticationHandler>(SessionAuthenticationHandler.SchemeName, _ => { });
        return services;
    }

    // [Guide §4.1, §4.3] One policy per permission code: the user needs that permission (loaded from AuthDb) and no pending password change.
    // Why: endpoints ask what a user may do, not their role name.
    // Standard: OWASP ASVS 5.0 V8.2.1.
    // Evidence: tests EveryEndpoint_HasPermissionPolicy, MustChangePassword_BlocksPermissionPolicies (R3).
    public static AuthorizationBuilder AddPermissionPolicies(this AuthorizationBuilder builder)
    {
        builder.AddPolicy(PermissionCodes.SessionPolicy, policy => policy.RequireAuthenticatedUser());
        foreach (var code in PermissionCodes.All)
        {
            builder.AddPolicy(code, policy => policy.RequireAssertion(context =>
                context.User.HasClaim(PermissionCodes.PermissionClaim, code)
                && !context.User.HasClaim(PermissionCodes.MustChangePasswordClaim, "true")));
        }
        return builder;
    }

    public static IServiceCollection AddCustomerServices(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<FieldEncryptionOptions>()
            .Bind(configuration.GetSection("FieldEncryption"))
            .Validate(o => IsKey(o.Key), "FieldEncryption__Key must be 32 random bytes, Base64 encoded.")
            .ValidateOnStart();
        services.AddOptions<SearchFingerprintOptions>()
            .Bind(configuration.GetSection("SearchFingerprint"))
            .Validate(o => IsKey(o.Key) && o.Key != configuration["FieldEncryption:Key"],
                "SearchFingerprint__Key must be 32 random bytes, Base64 encoded, and different from the field encryption key.")
            .ValidateOnStart();

        services.AddSingleton<FieldEncryptionService>();
        services.AddSingleton<SearchFingerprint>();
        services.AddScoped<CustomerAccess>();
        services.AddScoped<SearchRequestValidator>();
        services.AddScoped<CustomerSearchService>();
        services.AddScoped<SearchQuotaService>();
        services.AddScoped<CardRevealService>();
        services.AddScoped<CustomerSeeder>();
        services.AddScoped<SeedService>();
        return services;
    }

    private static bool IsKey(string value)
    {
        Span<byte> buffer = stackalloc byte[32];
        return Convert.TryFromBase64String(value, buffer, out var written) && written == 32;
    }
}
