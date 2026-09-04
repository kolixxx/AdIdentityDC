using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Core loop: login events -> LDAP groups -> session store -> push to plugin.
/// A successful 4769 only refreshes a matching existing session.
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
                _logger.LogError(
                    ex,
                    "Failed to handle authentication event {EventId} for {User}",
                    raw.EventId,
                    raw.User);
            }
        }
    }

    private async Task HandleAsync(RawLogonEvent raw, CancellationToken cancellationToken)
    {
        var user = NormalizeUser(raw.User);
        if (user.EndsWith('$') ||
            string.Equals(user, "ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase) ||
            IsLocalhost(raw.Ip))
        {
            return;
        }

        var domain = NormalizeDomain(raw.Domain);
        if (raw.EventId == 4769)
        {
            await HandleActivityRefreshAsync(raw, user, domain, cancellationToken);
            return;
        }

        var groups = await _groups.ResolveGroupsAsync(user, domain, cancellationToken);
        if (_options.MonitoredGroups.Count > 0)
        {
            groups = groups
                .Where(g => _options.MonitoredGroups.Contains(g, StringComparer.OrdinalIgnoreCase))
                .ToList();
        }

        var session = new Session
        {
            User = user,
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

    private async Task HandleActivityRefreshAsync(
        RawLogonEvent raw,
        string user,
        string domain,
        CancellationToken cancellationToken)
    {
        var existing = _store.GetAll().FirstOrDefault(s =>
            string.Equals(s.User, user, StringComparison.OrdinalIgnoreCase) &&
            string.Equals(s.Domain, domain, StringComparison.OrdinalIgnoreCase));

        // A 4769 must never create identity state by itself. It is high-volume
        // and includes service and machine activity that is not a user logon.
        if (existing is null)
        {
            _logger.LogDebug(
                "Ignoring 4769 for {Domain}\\{User}: no active session",
                domain,
                user);
            return;
        }

        // Do not move a user to another address from an activity event. A new
        // address needs a real login observation so D1/D4 rules are applied.
        if (!string.Equals(existing.Ip, raw.Ip, StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogDebug(
                "Ignoring 4769 for {Domain}\\{User}: activity IP {ActivityIp} does not match session IP {SessionIp}",
                domain,
                user,
                raw.Ip,
                existing.Ip);
            return;
        }

        var minimumInterval = TimeSpan.FromSeconds(
            Math.Max(0, _options.ActivityRefreshMinIntervalSec));
        if (minimumInterval > TimeSpan.Zero &&
            raw.Ts <= existing.Ts.Add(minimumInterval))
        {
            return;
        }

        var refreshed = new Session
        {
            User = existing.User,
            Domain = existing.Domain,
            Ip = existing.Ip,
            Groups = existing.Groups,
            Event = "refresh",
            Ts = raw.Ts,
            Dc = raw.Dc ?? existing.Dc,
            ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(_options.SessionTtlSec)
        };

        _store.Upsert(refreshed);
        await _plugin.UpsertAsync(refreshed, cancellationToken);
        _logger.LogInformation(
            "Session refreshed from 4769 {Domain}\\{User} {Ip}; expires {ExpiresAt}",
            refreshed.Domain,
            refreshed.User,
            refreshed.Ip,
            refreshed.ExpiresAt);
    }

    /// <summary>
    /// 4769 commonly reports TargetUserName as user@REALM while 4768 reports
    /// just user. Collapse UPN and DOMAIN\user forms to the account name so
    /// both events address the same session.
    /// </summary>
    private static string NormalizeUser(string user)
    {
        var trimmed = user.Trim();
        var slash = trimmed.LastIndexOf('\\');
        if (slash >= 0 && slash < trimmed.Length - 1)
        {
            trimmed = trimmed[(slash + 1)..];
        }

        var at = trimmed.IndexOf('@');
        if (at > 0)
        {
            trimmed = trimmed[..at];
        }

        return trimmed;
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
