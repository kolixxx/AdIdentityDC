using System.Threading.Channels;
using AdIdentity.Agent.Abstractions;
using Microsoft.Extensions.Logging;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Collector-side event source: HTTP ingest writes here, SessionPipeline reads.
/// </summary>
public sealed class IngestEventBus : IEventCollector
{
    private readonly Channel<RawLogonEvent> _channel = Channel.CreateUnbounded<RawLogonEvent>(
        new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
    private readonly ILogger<IngestEventBus> _logger;

    public IngestEventBus(ILogger<IngestEventBus> logger) => _logger = logger;

    public bool TryPublish(RawLogonEvent raw)
    {
        if (!_channel.Writer.TryWrite(raw))
        {
            _logger.LogWarning(
                "Ingest bus full or completed; dropped {EventId} for {Domain}\\{User}",
                raw.EventId,
                raw.Domain,
                raw.User);
            return false;
        }

        return true;
    }

    public async IAsyncEnumerable<RawLogonEvent> WatchAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (var raw in _channel.Reader.ReadAllAsync(cancellationToken))
        {
            yield return raw;
        }
    }
}
