using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Patterns;
using Microsoft.AspNetCore.Http;
using SBD.API.Common;
using SBD.API.Tests.Support;
using Xunit;
using Xunit.Abstractions;

namespace SBD.API.Tests;

public class Phase6RouteMatrixTests(AuthApiFactory factory, ITestOutputHelper output) : IClassFixture<AuthApiFactory>
{
    private const string AdminNetworkIp = "127.0.0.1";

    // Expected status per caller: anonymous, Normal, Accounting, Privileged, UserAdmin.
    private record Route(string Method, string Pattern, string Url, object? Body, int Anonymous, int Normal, int Accounting, int Privileged, int UserAdmin)
    {
        public int For(string? role) => role switch
        {
            null => Anonymous,
            RoleNames.Normal => Normal,
            RoleNames.Accounting => Accounting,
            RoleNames.Privileged => Privileged,
            _ => UserAdmin,
        };
    }

    private static readonly object NoBody = new { };
    private static readonly object SearchBody = new { lastName = "Zzzzqx" };

    // logout is last so the sessions used by the other rows stay valid until then.
    private static readonly Route[] Matrix =
    [
        new("POST", "customers/search", "/customers/search", SearchBody, 401, 200, 200, 200, 403),
        new("POST", "customers/{id:int}/card/reveal", "/customers/2147483647/card/reveal", NoBody, 401, 403, 404, 404, 403),
        new("GET", "localities", "/localities?state=VIC", null, 401, 200, 200, 200, 403),
        new("POST", "admin/users", "/admin/users", NoBody, 401, 403, 403, 403, 400),
        new("POST", "admin/users/{id}/role", "/admin/users/no-such-user/role", new { role = "Normal", approvalRef = "CHG-1" }, 401, 403, 403, 403, 404),
        new("POST", "admin/users/{id}/disable", "/admin/users/no-such-user/disable", new { approvalRef = "CHG-1" }, 401, 403, 403, 403, 404),
        new("POST", "admin/users/{id}/password-reset", "/admin/users/no-such-user/password-reset", new { temporaryPassword = "a-long-temporary-password" }, 401, 403, 403, 403, 404),
        new("POST", "admin/users/{id}/mfa-reset", "/admin/users/no-such-user/mfa-reset", NoBody, 401, 403, 403, 403, 404),
        new("POST", "admin/users/{id}/search-unlock", "/admin/users/no-such-user/search-unlock", NoBody, 401, 403, 403, 403, 404),
        new("GET", "auth/me", "/auth/me", null, 401, 200, 200, 200, 200),
        new("POST", "auth/change-password", "/auth/change-password", new { currentPassword = "wrong-current-password", newPassword = "brand-new-password-1" }, 401, 400, 400, 400, 400),
        new("POST", "auth/logout", "/auth/logout", null, 401, 204, 204, 204, 204),
    ];

    // Routes that are open to anyone on purpose; each is listed so the completeness check below knows it was decided, not forgotten.
    private static readonly Route[] AnonymousRoutes =
    [
        new("POST", "auth/login", "/auth/login", new { username = "nobody", password = "nobody-nobody-nobody" }, 401, 401, 401, 401, 401),
        new("POST", "auth/mfa/setup", "/auth/mfa/setup", new { mfaTicket = "none" }, 401, 401, 401, 401, 401),
        new("POST", "auth/mfa/confirm", "/auth/mfa/confirm", new { mfaTicket = "none", code = "000000" }, 401, 401, 401, 401, 401),
        new("POST", "auth/mfa", "/auth/mfa", new { mfaTicket = "none", code = "000000" }, 401, 401, 401, 401, 401),
    ];

    // R3 – Guide §4.3 every route is tried by anonymous, Normal, Accounting, Privileged and UserAdmin callers and returns the expected status
    [Fact]
    public async Task RouteMatrix_AllRolesAllEndpoints()
    {
        var roles = new string?[] { null, RoleNames.Normal, RoleNames.Accounting, RoleNames.Privileged, RoleNames.UserAdmin };
        var tokens = new Dictionary<string, AuthenticationHeaderValue?>();
        foreach (var role in roles.OfType<string>())
            tokens[role] = (await factory.SignInAsync(role)).Client.DefaultRequestHeaders.Authorization;

        var failures = new List<string>();
        output.WriteLine($"{"route",-48} {"anon",5} {"Normal",7} {"Account",8} {"Privil",7} {"UserAdm",8}");
        foreach (var route in Matrix.Concat(AnonymousRoutes))
        {
            var actual = new List<int>();
            foreach (var role in roles)
            {
                // Admin routes are called from the internal address for every role, so only the permission can refuse a non-admin.
                var ip = route.Pattern.StartsWith("admin/") ? AdminNetworkIp : AuthApiFactory.NextIp();
                var client = factory.CreateApiClient(remoteIp: ip);
                if (role is not null) client.DefaultRequestHeaders.Authorization = tokens[role];

                var request = new HttpRequestMessage(new HttpMethod(route.Method), route.Url);
                if (route.Body is not null) request.Content = JsonContent.Create(route.Body);
                var status = (int)(await client.SendAsync(request)).StatusCode;
                actual.Add(status);
                if (status != route.For(role)) failures.Add($"{route.Method} {route.Pattern} as {role ?? "anonymous"}: expected {route.For(role)}, got {status}");
            }
            output.WriteLine($"{route.Method + " " + route.Pattern,-48} {string.Join(' ', actual.Select(a => a.ToString().PadLeft(6)))}");
        }

        Assert.Empty(failures);
    }

    // R3 – Guide §4.3 every real route of the API appears in the matrix, so a new endpoint cannot be added without being tested for every role
    [Fact]
    public void Matrix_CoversEveryEndpoint()
    {
        var real = factory.Services.GetServices<EndpointDataSource>()
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Where(e => e.RoutePattern.RawText is { } text && !text.StartsWith("test/"))
            .Select(e => $"{e.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Single()} {e.RoutePattern.RawText}")
            .Order()
            .ToList();

        var listed = Matrix.Concat(AnonymousRoutes).Select(r => $"{r.Method} {r.Pattern}").Order().ToList();

        Assert.Equal(real, listed);
    }
}
