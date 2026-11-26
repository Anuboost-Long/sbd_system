/*
 * File: LocalitiesController.cs
 * Implements: Guide §2.1 approved locality list for the dropdowns.
 * Controls:   V6
 */
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SBD.API.Common;
using SBD.API.Services.Customers;
using SBD.API.Services.Customers.Dtos;

namespace SBD.API.Services.Localities;

[ApiController]
[Route("localities")]
public class LocalitiesController(CustomerAccess access) : ControllerBase
{
    private static readonly string[] States = ["NSW", "VIC", "QLD", "SA", "WA", "TAS", "NT", "ACT"];

    // [Guide §2.1] One list of approved suburb, state and postcode combinations feeds the dropdowns, the server check and storage.
    // Why: the interface, the API and the database can never disagree about what is valid.
    // Standard: Guide §2.1, §3.1.
    // Evidence: test Localities_ByState_ReturnsList (V6).
    [Authorize(PermissionCodes.CustomerSearch), HttpGet]
    public async Task<IActionResult> Get([FromQuery] string? state)
    {
        if (state is not null && !States.Contains(state)) return BadRequest(new { error = "Choose a valid state." });

        var localities = access.Localities(User.FindFirstValue(PermissionCodes.DataConnectionClaim));
        if (localities is null) return Forbid();

        // [Guide §3.2] parameterised
        var rows = await localities.AsNoTracking()
            .Where(l => state == null || l.State == state)
            .OrderBy(l => l.State).ThenBy(l => l.Suburb)
            .Select(l => new LocalityResult(l.Suburb, l.State, l.Postcode))
            .ToListAsync();
        return Ok(rows);
    }
}
