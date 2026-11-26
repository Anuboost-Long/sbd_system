using System.Text.Json;
using System.Text.Json.Serialization;

namespace SBD.API.Services.Customers.Dtos;

public class SearchRequest
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string? Phone { get; set; }
    public string? Unit { get; set; }
    public string? Street { get; set; }
    public string? State { get; set; }
    public string? Suburb { get; set; }
    public string? Postcode { get; set; }

    [JsonExtensionData]
    public Dictionary<string, JsonElement>? UnknownFields { get; set; }
}

public record NormalResult(
    int Id, string FirstName, string LastName, string? Unit, string Street,
    string Suburb, string State, string Postcode, string Phone);

public record AccountingResult(
    int Id, string FirstName, string LastName, string? Unit, string Street,
    string Suburb, string State, string Postcode, string Phone, string CardMasked);

public record PrivilegedResult(
    int Id, string FirstName, string LastName, string? Unit, string Street,
    string Suburb, string State, string Postcode, string Phone, string CardMasked,
    string CardNumber, string CardExpiry, string MedicalStatus);

public record RevealResponse(string CardNumber, string CardExpiry);

public record LocalityResult(string Suburb, string State, string Postcode);
