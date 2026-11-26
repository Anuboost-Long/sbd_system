/*
 * File: CustomersController.cs
 * Implements: Guide §2.2, §3.3, §4.3 customer search (POST) and card reveal endpoints.
 * Controls:   V1, E3, R1, R5
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SBD.API.Common;
using SBD.API.Services.Auth.Dtos;
using SBD.API.Services.Customers.Dtos;
using SBD.API.Services.Customers.Functions;
using SBD.API.SetUp;

namespace SBD.API.Services.Customers;

[ApiController]
[Route("customers")]
public class CustomersController(
    SearchRequestValidator validator,
    CustomerSearchService search,
    SearchQuotaService quota,
    CardRevealService reveal) : ControllerBase
{
    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier)!;
    private string? DataConnection => User.FindFirstValue(PermissionCodes.DataConnectionClaim);

    // [Guide §2.3] Search uses POST so names and phone numbers stay out of URLs, logs and browser history.
    // Why: query strings are copied into proxy logs, referrers and history.
    // Standard: Guide §2.3.
    // Evidence: test Search_OverGet_NotAllowed (E8).
    [Authorize(PermissionCodes.CustomerSearch), EnableRateLimiting(RateLimitSetup.SearchPolicy), HttpPost("search")]
    public async Task<IActionResult> Search([FromBody] SearchRequest request)
    {
        var (criteria, errors) = await validator.ValidateAsync(request, DataConnection);
        if (criteria is null) return ValidationProblem(new ValidationProblemDetails(errors));

        if (!await quota.IsAllowedAsync(UserId))
            return StatusCode(StatusCodes.Status429TooManyRequests, new ErrorResponse("Daily search limit reached. Ask a User Admin to unlock your search."));

        var outcome = await search.SearchAsync(UserId, DataConnection, criteria);
        if (outcome.Forbidden) return Forbid();

        await quota.RecordAsync(UserId, criteria, outcome.Results!.Count);
        return Ok(outcome.Results);
    }

    // [Guide §3.3, §4.4] Card reveal needs the customer.card.reveal permission, which the server reads from AuthDb; the logic is in CardRevealService.
    // Why: the permission is checked on the server for every call, never taken from the browser.
    // Standard: OWASP ASVS 5.0 V8.2.1.
    // Evidence: tests Reveal_Normal_Forbidden, Reveal_Accounting_Logged (R5).
    [Authorize(PermissionCodes.CustomerCardReveal), HttpPost("{id:int}/card/reveal")]
    public async Task<IActionResult> RevealCard(int id)
    {
        var outcome = await reveal.RevealAsync(UserId, DataConnection, id);
        return outcome.Status switch
        {
            RevealStatus.Ok => Ok(outcome.Card),
            RevealStatus.LimitReached => StatusCode(StatusCodes.Status429TooManyRequests, new ErrorResponse("Daily card reveal limit reached.")),
            RevealStatus.Forbidden => Forbid(),
            _ => NotFound(new ErrorResponse("Customer not found.")),
        };
    }
}
