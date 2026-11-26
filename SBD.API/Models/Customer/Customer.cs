using System.ComponentModel.DataAnnotations;

namespace SBD.API.Models.CustomerDb;

public class Customer
{
    public int CustomerId { get; set; }

    [Required, StringLength(50), RegularExpression(@"^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,49}$")]
    public string FirstName { get; set; } = string.Empty;

    [Required, StringLength(50), RegularExpression(@"^[\p{L}\p{M}][\p{L}\p{M} '\-]{0,49}$")]
    public string LastName { get; set; } = string.Empty;

    [StringLength(10), RegularExpression(@"^[\p{L}\d/\-]+$")]
    public string? Unit { get; set; }

    [Required, StringLength(60), RegularExpression(@"^[\p{L}\p{M}\d][\p{L}\p{M}\d '\-.]{0,59}$")]
    public string Street { get; set; } = string.Empty;

    public int LocalityId { get; set; }
    public Locality Locality { get; set; } = null!;

    [Required, RegularExpression(@"^\+\d{7,15}$")]
    public string Phone { get; set; } = string.Empty;

    [Required]
    public string MedicalStatusEnc { get; set; } = string.Empty;

    [Required]
    public string CardNumberEnc { get; set; } = string.Empty;

    [Required, RegularExpression(@"^\d{4}$")]
    public string CardLast4 { get; set; } = string.Empty;

    [Required]
    public string CardExpiryEnc { get; set; } = string.Empty;
}
