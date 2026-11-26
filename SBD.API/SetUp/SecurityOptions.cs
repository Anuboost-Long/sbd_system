using System.Net;

namespace SBD.API.SetUp;

public class SecurityOptions
{
    public string ApiKey { get; set; } = string.Empty;
    public string AllowedIps { get; set; } = string.Empty;
    public string AdminAllowedIps { get; set; } = string.Empty;

    public static IReadOnlySet<IPAddress> ParseIps(string commaSeparated) =>
        commaSeparated
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(ip => IPAddress.Parse(ip).MapToIPv6())
            .ToHashSet();
}
