using Serilog;
using Serilog.Events;

namespace SBD.API.SetUp;

public static class SerilogSetup
{
    public static void ConfigureBootstrapLogger()
    {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .Enrich.FromLogContext()
            .Enrich.WithProperty("App", "SBD.API")
            .WriteTo.File(
                outputTemplate: "[{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}",
                path: "Log/Debug/api-debug-.log",
                rollingInterval: RollingInterval.Day,
                shared: true)
            .CreateLogger();

    }

    public static IApplicationBuilder UseSerilogRequestLoggingSetup(this IApplicationBuilder app)
    {
        app.UseSerilogRequestLogging(options =>
        {
            options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";

            options.GetLevel = (http, _, exception) =>
            {
                var path = http.Request.Path.Value ?? "";
                if (path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase) ||
                    path.StartsWith("/favicon", StringComparison.OrdinalIgnoreCase))
                {
                    return LogEventLevel.Debug;
                }

                return exception == null ? LogEventLevel.Information : LogEventLevel.Error;
            };

            options.EnrichDiagnosticContext = (context, http) =>
            {
                context.Set("trace_id", http.TraceIdentifier);
                context.Set("user", http.User.Identity?.Name ?? "anonymous");
                context.Set("client_ip", http.Connection.RemoteIpAddress?.ToString() ?? "unknown");
                context.Set("user_agent", http.Request.Headers.UserAgent.ToString());
            };
        });

        return app;
    }
}
