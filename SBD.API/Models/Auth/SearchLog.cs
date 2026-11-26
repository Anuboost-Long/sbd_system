namespace SBD.API.Models.AuthDb;

public class SearchLog
{
    public long SearchId { get; set; }
    public string UserId { get; set; } = string.Empty;
    public DateTime OccurredUtc { get; set; }
    public bool UsedWildcard { get; set; }
    public byte PrefixLength { get; set; }
    public byte[]? PrefixFingerprint { get; set; }
    public short ResultCount { get; set; }
}
