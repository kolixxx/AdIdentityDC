using AdIdentity.Agent.Abstractions;
using Microsoft.Extensions.Logging;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Placeholder until Security Event Log subscription (4768/4624) is implemented.
/// </summary>
public sealed class StubEventCollector : IEventCollector
{
    private readonly ILogger<StubEventCollector> _logger;

    public StubEventCollector(ILogger<StubEventCollector> logger)
    {
        _logger = logger;
    }

    public async IAsyncEnumerable<RawLogonEvent> WatchAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        _logger.LogWarning("StubEventCollector is active — no real Windows events are read yet");
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromHours(24), cancellationToken);
            yield break;
        }
    }
}
