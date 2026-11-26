namespace SBD.API.Services.Customers.Functions;

public record SearchTerm(string Value, bool IsPrefix);

public record SearchCriteria(
    SearchTerm? FirstName,
    SearchTerm? LastName,
    SearchTerm? Phone,
    string? Unit,
    string? Street,
    string? State,
    string? Suburb,
    string? Postcode)
{
    public IEnumerable<SearchTerm> Prefixes => new[] { FirstName, LastName, Phone }.Where(t => t is { IsPrefix: true })!;
}
