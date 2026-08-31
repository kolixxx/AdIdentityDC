using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Session state keyed by domain\user. v1 contract: one user holds one active IP.
/// Expired entries are dropped on read so resync never resurrects them downstream.
/// </summary>
public sealed class InMemorySessionStore : ISessionStore
{
    private readonly Dictionary<string, Session> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();

    public int Count
    {
        get
        {
            lock (_gate)
            {
                Prune();
                return _sessions.Count;
            }
        }
    }

    public IReadOnlyCollection<Session> GetAll()
    {
        lock (_gate)
        {
            Prune();
            return _sessions.Values.ToList();
        }
    }

    public Session? Upsert(Session session)
    {
        lock (_gate)
        {
            Prune();
            EvictIp(session.Ip, MakeKey(session.User, session.Domain));
            _sessions[MakeKey(session.User, session.Domain)] = session;
            return session;
        }
    }

    public bool Remove(string user, string domain, string ip)
    {
        lock (_gate)
        {
            var key = MakeKey(user, domain);
            if (!_sessions.TryGetValue(key, out var existing))
            {
                return false;
            }

            // Ignore a stale removal for an address the user no longer holds.
            if (!string.IsNullOrEmpty(ip) && !string.Equals(existing.Ip, ip, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return _sessions.Remove(key);
        }
    }

    /// <summary>
    /// Drop other users still mapped to this address, otherwise a recycled DHCP lease
    /// would let the new user inherit the previous user's group aliases.
    /// </summary>
    private void EvictIp(string ip, string keepKey)
    {
        if (string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        var stale = _sessions
            .Where(kv => !kv.Key.Equals(keepKey, StringComparison.OrdinalIgnoreCase)
                         && string.Equals(kv.Value.Ip, ip, StringComparison.OrdinalIgnoreCase))
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in stale)
        {
            _sessions.Remove(key);
        }
    }

    private void Prune()
    {
        var now = DateTimeOffset.UtcNow;
        var expired = _sessions
            .Where(kv => kv.Value.ExpiresAt is not null && kv.Value.ExpiresAt <= now)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in expired)
        {
            _sessions.Remove(key);
        }
    }

    private static string MakeKey(string user, string domain) => $"{domain}\\{user}";
}
