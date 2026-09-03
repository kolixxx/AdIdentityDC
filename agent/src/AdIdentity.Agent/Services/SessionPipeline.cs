using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Core loop: events -> LDAP groups -> session store -> push to plugin.
/// </summary>
public sealed class SessionPipeline
{
    private readonly IEventCollector _events;
    private readonly IGroupResolver _groups;
    private readonly ISessionStore _store;
    private readonly IPluginClient _plugin;
    private readonly AgentOptions _options;
    private readonly ILogger<SessionPipeline> _logger;

    public SessionPipeline(
        IEventCollector events,
        IGroupResolver groups,
        ISessionStore store,
        IPluginClient plugin,
        IOptions<AgentOptions> options,
        ILogger<SessionPipeline> logger)
    {
        _events = events;
        _groups = groups;
        _store = store;
        _plugin = plugin;
        _options = options.Value;
        _logger = logger;
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        await foreach (var raw in _events.WatchAsync(cancellationToken))
        {
            try
            {
                await HandleAsync(raw, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Failed to handle logon event for {User}", raw.User);
            }
        }
    }

    private async Task HandleAsync(RawLogonEvent raw, CancellationToken cancellationToken)
    {
        if (raw.User.EndsWith('$') ||
            string.Equals(raw.User, "ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase) ||
            IsLocalhost(raw.Ip))
        {
            return;
        }

        var domain = NormalizeDomain(raw.Domain);

        var groups = await _groups.ResolveGroupsAsync(raw.User, domain, cancellationToken);
        if (_options.MonitoredGroups.Count > 0)
        {
            groups = groups
                .Where(g => _options.MonitoredGroups.Contains(g, StringComparer.OrdinalIgnoreCase))
                .ToList();
        }

        var session = new Session
        {
            User = raw.User,
            Domain = domain,
            Ip = raw.Ip,
            Groups = groups,
            Event = "login",
            Ts = raw.Ts,
            Dc = raw.Dc,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.SessionTtlSec)
        };

        _store.Upsert(session);
        await _plugin.UpsertAsync(session, cancellationToken);
        _logger.LogInformation(
            "Session upserted {Domain}\\{User} {Ip} groups={GroupCount}",
            session.Domain,
            session.User,
            session.Ip,
            session.Groups.Count);
    }

    /// <summary>
    /// 4768 reports the Kerberos realm (INTERNAL.LAB) while 4624 reports the short name
    /// (INTERNAL), which would key the same person as two sessions. Collapse to the short
    /// upper-case form. Assumes the first DNS label matches the NetBIOS name.
    /// </summary>
    private static string NormalizeDomain(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain))
        {
            return "";
        }

        var trimmed = domain.Trim().TrimEnd('.');
        var dot = trimmed.IndexOf('.');
        if (dot > 0)
        {
            trimmed = trimmed[..dot];
        }

        return trimmed.ToUpperInvariant();
    }

    private static bool IsLocalhost(string ip) =>
        string.IsNullOrWhiteSpace(ip) ||
        ip is "-" or "::1" or "127.0.0.1";
}
