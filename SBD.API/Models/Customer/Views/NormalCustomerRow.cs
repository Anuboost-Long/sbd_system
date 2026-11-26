namespace SBD.API.Models.CustomerDb.Views;

public class NormalCustomerRow : ICustomerRow
{
    public int CustomerId { get; set; }
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string? Unit { get; set; }
    public string Street { get; set; } = string.Empty;
    public string Suburb { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string Postcode { get; set; } = string.Empty;
    public string Phone { get; set; } = string.Empty;
}
