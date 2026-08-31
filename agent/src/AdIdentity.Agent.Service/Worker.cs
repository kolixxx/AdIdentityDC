using AdIdentity.Agent.Services;

namespace AdIdentity.Agent.Service;

public sealed class Worker : BackgroundService
{
    private readonly SessionPipeline _pipeline;
    private readonly ILogger<Worker> _logger;

    public Worker(SessionPipeline pipeline, ILogger<Worker> logger)
    {
        _pipeline = pipeline;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("AdIdentity Agent worker starting");
        await _pipeline.RunAsync(stoppingToken);
        _logger.LogInformation("AdIdentity Agent worker stopped");
    }
}
