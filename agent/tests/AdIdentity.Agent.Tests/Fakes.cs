using System.Runtime.CompilerServices;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// Replays a fixed list of events, then completes so RunAsync returns.
/// </summary>
internal sealed class FakeEventCollector : IEventCollector
{
    private readonly IReadOnlyList<RawLogonEvent> _events;

    public FakeEventCollector(params RawLogonEvent[] events) => _events = events;

    public async IAsyncEnumerable<RawLogonEvent> WatchAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var raw in _events)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return raw;
        }

        await Task.CompletedTask;
    }
}

internal sealed class FakeGroupResolver : IGroupResolver
{
    private readonly IReadOnlyList<string> _groups;

    public FakeGroupResolver(params string[] groups) => _groups = groups;

    public int Calls { get; private set; }

    public Task<IReadOnlyList<string>> ResolveGroupsAsync(
        string user,
        string domain,
        CancellationToken cancellationToken)
    {
        Calls++;
        return Task.FromResult(_groups);
    }
}

/// <summary>
/// Mirrors FileSessionStore semantics that the pipeline depends on: expired
/// sessions disappear from GetAll, and one IP belongs to one user.
/// </summary>
internal sealed class FakeSessionStore : ISessionStore
{
    private readonly Dictionary<string, Session> _sessions = new(StringComparer.OrdinalIgnoreCase);

    public int Count => GetAll().Count;

    public IReadOnlyCollection<Session> GetAll()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var key in _sessions
                     .Where(kv => kv.Value.ExpiresAt is not null && kv.Value.ExpiresAt <= now)
                     .Select(kv => kv.Key)
                     .ToList())
        {
            _sessions.Remove(key);
        }

        return _sessions.Values.ToList();
    }

    public Session? Upsert(Session session)
    {
        var key = Key(session.User, session.Domain);
        foreach (var stale in _sessions
                     .Where(kv => !kv.Key.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                                  string.Equals(kv.Value.Ip, session.Ip, StringComparison.OrdinalIgnoreCase))
                     .Select(kv => kv.Key)
                     .ToList())
        {
            _sessions.Remove(stale);
        }

        _sessions[key] = session;
        return session;
    }

    public bool Remove(string user, string domain, string ip) => _sessions.Remove(Key(user, domain));

    /// <summary>Force a stored session to look expired, without waiting for the TTL.</summary>
    public void ExpireAll()
    {
        foreach (var key in _sessions.Keys.ToList())
        {
            var session = _sessions[key];
            _sessions[key] = Clone(session, DateTimeOffset.UtcNow.AddSeconds(-1));
        }
    }

    private static Session Clone(Session session, DateTimeOffset expiresAt) => new()
    {
        User = session.User,
        Domain = session.Domain,
        Ip = session.Ip,
        Groups = session.Groups,
        Event = session.Event,
        Ts = session.Ts,
        Dc = session.Dc,
        ExpiresAt = expiresAt
    };

    private static string Key(string user, string domain) => $"{domain}\\{user}";
}

internal sealed class FakePluginClient : IPluginClient
{
    public List<Session> Upserts { get; } = new();

    public List<string> Removals { get; } = new();

    public Task UpsertAsync(Session session, CancellationToken cancellationToken)
    {
        Upserts.Add(session);
        return Task.CompletedTask;
    }

    public Task RemoveAsync(string user, string domain, string ip, string reason, CancellationToken cancellationToken)
    {
        Removals.Add($"{domain}\\{user} {ip} {reason}");
        return Task.CompletedTask;
    }
}
