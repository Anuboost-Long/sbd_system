/*
 * File: GlobalExceptionHandler.cs
 * Implements: Guide §3.2, §5 generic error replies; details stay in the server log.
 * Controls:   V9
 */
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace SBD.API.Middleware;

public class GlobalExceptionHandler(ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    // [Guide §3.2, §5] Turn any unhandled error into one generic 500 reply with a correlation ID; log the details on the server only.
    // Why: stack traces, SQL text and connection details help an attacker. Staff can quote the ID so support finds the log line.
    // Standard: OWASP Error Handling Cheat Sheet; OWASP ASVS 5.0 V16.
    // Evidence: test DbError_ReturnsGenericMessage (V9).
    public async ValueTask<bool> TryHandleAsync(HttpContext context, Exception exception, CancellationToken cancellationToken)
    {
        logger.LogError(exception, "Unhandled error, correlation {CorrelationId}", context.TraceIdentifier);

        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new ProblemDetails
        {
            Status = StatusCodes.Status500InternalServerError,
            Title = "Something went wrong.",
            Extensions = { ["correlationId"] = context.TraceIdentifier },
        }, cancellationToken);

        return true;
    }
}
