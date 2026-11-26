using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using SBD.API.Tests.Support;
using Xunit;

namespace SBD.API.Tests;

public class Phase2Tests(ApiWithTestEndpointsFactory factory) : IClassFixture<ApiWithTestEndpointsFactory>
{
    // E8 – Guide §2.3 security headers on every response
    [Fact]
    public async Task SecurityHeaders_Present()
    {
        var response = await factory.CreateApiClient().GetAsync("/test/ok");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Equal("default-src 'none'; frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Equal("no-store", response.Headers.GetValues("Cache-Control").Single());
    }

    // E7 – Guide §2.3 HSTS tells browsers to use HTTPS only
    [Fact]
    public async Task Hsts_HeaderPresent()
    {
        var client = factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://api.example.test"),
            AllowAutoRedirect = false,
        });
        client.DefaultRequestHeaders.Add("X-Api-Key", ApiFactory.ApiKey);

        var response = await client.GetAsync("/test/ok");

        Assert.True(response.Headers.Contains("Strict-Transport-Security"));
    }

    // E6 – Guide §2.3 only the allowlisted address may call the API
    [Fact]
    public async Task NotAllowlistedIp_403()
    {
        var blocked = await factory.CreateApiClient(remoteIp: "10.0.0.5").GetAsync("/test/ok");
        var allowed = await factory.CreateApiClient(remoteIp: "127.0.0.1").GetAsync("/test/ok");

        Assert.Equal(HttpStatusCode.Forbidden, blocked.StatusCode);
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
    }

    // E6 – Guide §2.3 API key required
    [Fact]
    public async Task MissingApiKey_401()
    {
        var response = await factory.CreateApiClient(apiKey: null).GetAsync("/test/ok");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // E6 – Guide §2.3 wrong API key refused
    [Fact]
    public async Task WrongApiKey_401()
    {
        var response = await factory.CreateApiClient(apiKey: "wrong-key").GetAsync("/test/ok");

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    // V9 – Guide §3.2, §5 generic error reply, no SQL or secrets
    [Fact]
    public async Task DbError_ReturnsGenericMessage()
    {
        var response = await factory.CreateApiClient().GetAsync("/test/boom");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Contains("correlationId", body);
        Assert.DoesNotContain("hunter2", body);
        Assert.DoesNotContain("SELECT", body);
        Assert.DoesNotContain("Server=", body);
        Assert.DoesNotContain("InvalidOperationException", body);
    }

    // A7 – Guide §2.5 login limited to 10 per minute per address
    [Fact]
    public async Task LoginRateLimit_11thRequest_429()
    {
        var client = factory.CreateApiClient(remoteIp: "127.0.0.1");

        for (var attempt = 1; attempt <= 10; attempt++)
            Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/test/login", null)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsync("/test/login", null)).StatusCode);
    }

    // E3 – Guide §2.2 search limited to 30 per minute per user
    [Fact]
    public async Task SearchRateLimit_31st_429()
    {
        var client = factory.CreateApiClient(user: "rate-limit-user");

        for (var attempt = 1; attempt <= 30; attempt++)
            Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/test/search", null)).StatusCode);

        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.PostAsync("/test/search", null)).StatusCode);

        var otherUser = factory.CreateApiClient(user: "another-user");
        Assert.Equal(HttpStatusCode.OK, (await otherUser.PostAsync("/test/search", null)).StatusCode);
    }

    // R3 – Guide §4.3 unauthenticated call to a protected route is refused
    [Fact]
    public async Task ProtectedRoute_WithoutLogin_401()
    {
        var response = await factory.CreateApiClient().PostAsync("/test/search", null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

public class DenyByDefaultTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    // R3 – Guide §4.3, §5 every real endpoint has a permission policy or is explicitly anonymous
    [Fact]
    public void EveryEndpoint_HasPermissionPolicy()
    {
        var endpoints = factory.Services.GetServices<EndpointDataSource>().SelectMany(source => source.Endpoints);

        var unprotected = endpoints
            .Where(endpoint => endpoint.Metadata.GetMetadata<IAllowAnonymous>() is null
                && string.IsNullOrEmpty(endpoint.Metadata.GetMetadata<IAuthorizeData>()?.Policy))
            .Select(endpoint => endpoint.DisplayName)
            .ToList();

        Assert.Empty(unprotected);
    }

    // R3 – Guide §4.3, §5 fallback policy denies anyone who is not signed in
    [Fact]
    public async Task FallbackPolicy_RequiresAuthenticatedUser()
    {
        var provider = factory.Services.GetRequiredService<IAuthorizationPolicyProvider>();

        var fallback = await provider.GetFallbackPolicyAsync();

        Assert.NotNull(fallback);
        Assert.Contains(fallback.Requirements, requirement => requirement is Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement);
    }
}
