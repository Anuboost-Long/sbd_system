using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SBD.API.Tests.Support;

public class ApiFactory : WebApplicationFactory<Program>
{
    public const string ApiKey = "test-api-key-not-a-secret";

    static ApiFactory()
    {
        Environment.SetEnvironmentVariable("Security__ApiKey", ApiKey);
        Environment.SetEnvironmentVariable("Security__AllowedIps", string.Join(",", Enumerable.Range(1, 80).Select(n => $"127.0.0.{n}")));
        Environment.SetEnvironmentVariable("Security__AdminAllowedIps", "127.0.0.1");
    }

    public HttpClient CreateApiClient(string? remoteIp = null, string? apiKey = ApiKey, string? user = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false,
        });
        if (apiKey is not null) client.DefaultRequestHeaders.Add("X-Api-Key", apiKey);
        if (remoteIp is not null) client.DefaultRequestHeaders.Add(RemoteIpFilter.Header, remoteIp);
        if (user is not null) client.DefaultRequestHeaders.Add(TestAuthHandler.UserHeader, user);
        return client;
    }

    // The daily inactivity job is removed here: tests call InactiveAccountService directly, and a start-up run would touch the shared database mid-test.
    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureServices(services =>
        {
            services.AddSingleton<Microsoft.AspNetCore.Hosting.IStartupFilter, RemoteIpFilter>();
            services.Remove(services.Single(d => d.ImplementationType == typeof(SBD.API.Services.Admin.InactiveAccountJob)));
        });
}

public class RemoteIpFilter : Microsoft.AspNetCore.Hosting.IStartupFilter
{
    public const string Header = "X-Test-RemoteIp";

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            var ip = context.Request.Headers[Header].FirstOrDefault() ?? "127.0.0.1";
            context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
            await nextMiddleware();
        });
        next(app);
    };
}
