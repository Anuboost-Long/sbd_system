using System.ComponentModel.DataAnnotations;

namespace SBD.API.Models.CustomerDb;

public class Locality
{
    public int LocalityId { get; set; }

    [Required, StringLength(46), RegularExpression(@"^[\p{L} '\-]+$")]
    public string Suburb { get; set; } = string.Empty;

    [Required, RegularExpression("^(NSW|VIC|QLD|SA|WA|TAS|NT|ACT)$")]
    public string State { get; set; } = string.Empty;

    [Required, RegularExpression(@"^\d{4}$")]
    public string Postcode { get; set; } = string.Empty;
}
