/*
 * File: Program.cs
 * Implements: Guide §2.3, §4.3, §5 TLS 1.3 only, HTTPS redirect, HSTS, security middleware order and deny-by-default authorisation.
 * Controls:   E6, E7, E8, R3
 */
using Microsoft.AspNetCore.Authorization;
using Serilog;
using SBD.API.Contexts;
using SBD.API.Middleware;
using SBD.API.Services.Seed;
using SBD.API.SetUp;
using System.Security.Authentication;

EnvLoader.Load();
SerilogSetup.ConfigureBootstrapLogger();

var builder = WebApplication.CreateBuilder(args);
builder.Host.UseSerilog();

// [Guide §2.3] Accept TLS 1.3 only on the API's HTTPS port.
// Why: removes older protocol weaknesses; stricter than the NIST SP 800-52 Rev. 2 TLS 1.2 baseline.
// Standard: ASD ISM-1139, ISM-1369, ISM-1372; NIST SP 800-52 Rev. 2.
// Evidence: manual check, openssl s_client -tls1_2 refused and -tls1_3 accepted (E7).
builder.WebHost.ConfigureKestrel(kestrel =>
    kestrel.ConfigureHttpsDefaults(https => https.SslProtocols = SslProtocols.Tls13));
builder.Services.AddHttpsRedirection(options => options.HttpsPort = builder.Configuration.GetValue("HttpsPort", 7044));

builder.Services.AddDatabaseContexts(builder.Configuration, logSql: builder.Environment.IsDevelopment());
builder.Services.AddIdentitySetup();
builder.Services.AddSecurityServices(builder.Configuration);
builder.Services.AddCustomerServices(builder.Configuration);
builder.Services.AddControllers();

builder.Services.AddAuthenticationServices();

// [Guide §4.3, §5] Deny by default: any endpoint without its own permission policy needs a signed-in user.
// Why: a forgotten attribute can never expose a route (fail-safe default).
// Standard: OWASP ASVS 5.0 V8.2.1; Saltzer & Schroeder (1975).
// Evidence: test EveryEndpoint_HasPermissionPolicy (R3).
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
    .AddPermissionPolicies();

var app = builder.Build();

if (args.Contains("seed"))
{
    using var scope = app.Services.CreateScope();
    await scope.ServiceProvider.GetRequiredService<SeedService>().RunAsync();
    Log.CloseAndFlush();
    return;
}

// [Guide §2.3] HTTPS redirect and HSTS (browsers must use HTTPS from then on).
// Why: stops plain-text requests and downgrade attacks.
// Standard: ASD ISM-1139; NIST SP 800-52 Rev. 2.
// Evidence: manual check of the Strict-Transport-Security header and redirect (E7).
app.UseHttpsRedirection();
app.UseHsts();

app.UseSerilogRequestLoggingSetup();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<IpAllowlistMiddleware>();
app.UseMiddleware<ApiKeyMiddleware>();
app.UseExceptionHandler();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();

app.MapControllers();

try
{
    app.Run();
}
finally
{
    Log.CloseAndFlush();
}

public partial class Program;
