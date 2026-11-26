namespace SBD.API.Models.CustomerDb.Views;

public class PrivilegedCustomerRow : ICustomerRow, ICardRow
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
    public string CardLast4 { get; set; } = string.Empty;
    public string CardNumberEnc { get; set; } = string.Empty;
    public string CardExpiryEnc { get; set; } = string.Empty;
    public string MedicalStatusEnc { get; set; } = string.Empty;
}
