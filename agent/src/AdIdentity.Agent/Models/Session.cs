namespace AdIdentity.Agent.Models;

public sealed class Session
{
    public required string User { get; init; }
    public required string Domain { get; init; }
    public required string Ip { get; init; }
    public required IReadOnlyList<string> Groups { get; init; }
    public required string Event { get; init; }
    public required DateTimeOffset Ts { get; init; }
    public string? Dc { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }

    public object ToContractPayload() => new
    {
        user = User,
        domain = Domain,
        ip = Ip,
        groups = Groups,
        @event = Event,
        ts = Ts.UtcDateTime.ToString("o"),
        dc = Dc,
        expires_at = ExpiresAt?.UtcDateTime.ToString("o")
    };
}
