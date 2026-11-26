namespace SBD.API.Models.CustomerDb.Views;

public interface ICustomerRow
{
    int CustomerId { get; }
    string FirstName { get; }
    string LastName { get; }
    string? Unit { get; }
    string Street { get; }
    string Suburb { get; }
    string State { get; }
    string Postcode { get; }
    string Phone { get; }
}

public interface ICardRow
{
    int CustomerId { get; }
    string CardLast4 { get; }
    string CardNumberEnc { get; }
    string CardExpiryEnc { get; }
}
