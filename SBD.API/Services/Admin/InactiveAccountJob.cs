/*
 * File: InactiveAccountJob.cs
 * Implements: Guide §4.2 daily background run of the 90-day inactivity check.
 * Controls:   E10
 */
namespace SBD.API.Services.Admin;

public class InactiveAccountJob(IServiceScopeFactory scopes, ILogger<InactiveAccountJob> logger) : BackgroundService
{
    // [Guide §4.2] Run the 90-day check at start-up and then every 24 hours; errors are logged.
    // Why: the rule runs without anyone remembering to do it.
    // Standard: ISO/IEC 27001:2022.
    // Evidence: test InactiveAccount_Disabled (E10).
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromDays(1));
        do
        {
            try
            {
                using var scope = scopes.CreateScope();
                var disabled = await scope.ServiceProvider.GetRequiredService<InactiveAccountService>().DisableInactiveAsync();
                logger.LogInformation("Inactive account check finished, {Count} account(s) disabled", disabled);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Inactive account check failed");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
