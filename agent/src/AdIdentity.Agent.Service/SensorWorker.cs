using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Services;

namespace AdIdentity.Agent.Service;

/// <summary>
/// Sensor role: read Security events on this DC and forward them to the Collector.
/// </summary>
public sealed class SensorWorker : BackgroundService
{
    private readonly IEventCollector _events;
    private readonly CollectorIngestClient _ingest;
    private readonly ILogger<SensorWorker> _logger;

    public SensorWorker(
        IEventCollector events,
        CollectorIngestClient ingest,
        ILogger<SensorWorker> logger)
    {
        _events = events;
        _ingest = ingest;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AdIdentity Sensor worker starting");
        await foreach (var raw in _events.WatchAsync(stoppingToken))
        {
            try
            {
                await _ingest.ForwardAsync(raw, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(
                    ex,
                    "Failed to forward event {EventId} for {Domain}\\{User}",
                    raw.EventId,
                    raw.Domain,
                    raw.User);
            }
        }

        _logger.LogInformation("AdIdentity Sensor worker stopped");
    }
}
