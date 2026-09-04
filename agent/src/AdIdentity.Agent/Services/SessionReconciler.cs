using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Periodically re-pushes every active session to the plugin, so the plugin recovers
/// state it missed while it was down or unreachable. Sessions keep their original
/// ExpiresAt, so a re-push never extends a TTL.
/// This is the agent-side half of the sync contract; the plugin-side pull ("Resync
/// from Agent") stays a manual operator action, so only one side runs on a schedule.
/// </summary>
public sealed class SessionReconciler : BackgroundService
{
    private readonly ISessionStore _store;
    private readonly IPluginClient _plugin;
    private readonly AgentOptions _options;
    private readonly ILogger<SessionReconciler> _logger;

    public SessionReconciler(
        ISessionStore store,
        IPluginClient plugin,
        IOptions<AgentOptions> options,
        ILogger<SessionReconciler> logger)
    {
        _store = store;
        _plugin = plugin;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var intervalSec = _options.ReconcileIntervalSec;
        if (intervalSec <= 0)
        {
            _logger.LogInformation("Session reconcile disabled (ReconcileIntervalSec=0)");
            return;
        }

        var interval = TimeSpan.FromSeconds(intervalSec);
        _logger.LogInformation("Session reconcile every {Interval}", interval);

        using var timer = new PeriodicTimer(interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await ReconcileAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Session reconcile pass failed");
            }
        }
    }

    private async Task ReconcileAsync(CancellationToken cancellationToken)
    {
        var sessions = _store.GetAll();
        if (sessions.Count == 0)
        {
            return;
        }

        var pushed = 0;
        var failed = 0;

        foreach (var session in sessions)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                await _plugin.UpsertAsync(AsRefresh(session), cancellationToken);
                pushed++;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                failed++;
                _logger.LogWarning(
                    ex,
                    "Reconcile push failed for {User}@{Domain} {Ip}",
                    session.User, session.Domain, session.Ip);
            }
        }

        if (failed > 0)
        {
            _logger.LogWarning("Session reconcile: {Pushed} pushed, {Failed} failed", pushed, failed);
        }
        else
        {
            _logger.LogDebug("Session reconcile: {Pushed} pushed", pushed);
        }
    }

    private static Session AsRefresh(Session session) => new()
    {
        User = session.User,
        Domain = session.Domain,
        Ip = session.Ip,
        Groups = session.Groups,
        Event = "refresh",
        Ts = session.Ts,
        Dc = session.Dc,
        ExpiresAt = session.ExpiresAt
    };
}
