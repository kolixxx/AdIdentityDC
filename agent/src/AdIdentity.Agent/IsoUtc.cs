namespace AdIdentity.Agent;

internal static class IsoUtc
{
    /// <summary>
    /// UTC ISO-8601 with at most 6 fractional digits so OPNsense/Python
    /// <c>datetime.fromisoformat</c> always parses Agent timestamps.
    /// </summary>
    private const string Pattern = "yyyy-MM-dd'T'HH:mm:ss.ffffff'Z'";

    public static string Format(DateTimeOffset value) =>
        value.UtcDateTime.ToString(Pattern);

    public static bool TryParse(string? value, out DateTimeOffset result)
    {
        result = default;
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return DateTimeOffset.TryParse(
            value,
            System.Globalization.CultureInfo.InvariantCulture,
            System.Globalization.DateTimeStyles.RoundtripKind,
            out result);
    }
}
