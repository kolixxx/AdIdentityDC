using AdIdentity.Agent.Models;

namespace AdIdentity.Agent.Abstractions;

public interface IEventCollector
{
    /// <summary>
    /// Watch Security log / auth events and yield raw user+ip observations.
    /// </summary>
    IAsyncEnumerable<RawLogonEvent> WatchAsync(CancellationToken cancellationToken);
}

public sealed class RawLogonEvent
{
    public required string User { get; init; }
    public required string Domain { get; init; }
    public required string Ip { get; init; }
    public required int EventId { get; init; }
    public int? LogonType { get; init; }
    public required DateTimeOffset Ts { get; init; }
    public string? Dc { get; init; }
}
