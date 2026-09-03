using System.Text.Json;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Same contract as the in-memory store, but snapshots to disk so a service
/// restart does not hand the plugin an empty resync and wipe live aliases (D8).
/// </summary>
public sealed class FileSessionStore : ISessionStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly Dictionary<string, Session> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly string _path;
    private readonly ILogger<FileSessionStore> _logger;

    public FileSessionStore(ILogger<FileSessionStore> logger)
    {
        _logger = logger;
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AdIdentity");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "sessions.json");
        LoadUnlocked();
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                if (Prune())
                {
                    SaveUnlocked();
                }

                return _sessions.Count;
            }
        }
    }

    public IReadOnlyCollection<Session> GetAll()
    {
        lock (_gate)
        {
            if (Prune())
            {
                SaveUnlocked();
            }

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
            SaveUnlocked();
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

            if (!string.IsNullOrEmpty(ip) && !string.Equals(existing.Ip, ip, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            if (!_sessions.Remove(key))
            {
                return false;
            }

            SaveUnlocked();
            return true;
        }
    }

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

    private bool Prune()
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

        return expired.Count > 0;
    }

    private void LoadUnlocked()
    {
        if (!File.Exists(_path))
        {
            _logger.LogInformation("Session store file not found at {Path}; starting empty", _path);
            return;
        }

        try
        {
            var json = File.ReadAllText(_path);
            var payload = JsonSerializer.Deserialize<StoreFile>(json, JsonOptions);
            if (payload?.Sessions is null)
            {
                return;
            }

            var now = DateTimeOffset.UtcNow;
            var loaded = 0;
            foreach (var row in payload.Sessions)
            {
                if (string.IsNullOrWhiteSpace(row.User) || string.IsNullOrWhiteSpace(row.Domain) ||
                    string.IsNullOrWhiteSpace(row.Ip))
                {
                    continue;
                }

                if (row.ExpiresAt is not null && row.ExpiresAt <= now)
                {
                    continue;
                }

                var session = new Session
                {
                    User = row.User,
                    Domain = row.Domain,
                    Ip = row.Ip,
                    Groups = (IReadOnlyList<string>)(row.Groups ?? new List<string>()),
                    Event = string.IsNullOrWhiteSpace(row.Event) ? "login" : row.Event,
                    Ts = row.Ts ?? DateTimeOffset.UtcNow,
                    Dc = row.Dc,
                    ExpiresAt = row.ExpiresAt
                };
                _sessions[MakeKey(session.User, session.Domain)] = session;
                loaded++;
            }

            _logger.LogInformation("Loaded {Count} sessions from {Path}", loaded, _path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load session store from {Path}; starting empty", _path);
            _sessions.Clear();
        }
    }

    private void SaveUnlocked()
    {
        try
        {
            var payload = new StoreFile
            {
                UpdatedAt = DateTimeOffset.UtcNow,
                Sessions = _sessions.Values.Select(s => new StoredSession
                {
                    User = s.User,
                    Domain = s.Domain,
                    Ip = s.Ip,
                    Groups = s.Groups.ToList(),
                    Event = s.Event,
                    Ts = s.Ts,
                    Dc = s.Dc,
                    ExpiresAt = s.ExpiresAt
                }).ToList()
            };
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(payload, JsonOptions));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist session store to {Path}", _path);
        }
    }

    private static string MakeKey(string user, string domain) => $"{domain}\\{user}";

    private sealed class StoreFile
    {
        public DateTimeOffset? UpdatedAt { get; set; }
        public List<StoredSession> Sessions { get; set; } = new();
    }

    private sealed class StoredSession
    {
        public string User { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Ip { get; set; } = "";
        public List<string>? Groups { get; set; }
        public string Event { get; set; } = "login";
        public DateTimeOffset? Ts { get; set; }
        public string? Dc { get; set; }
        public DateTimeOffset? ExpiresAt { get; set; }
    }
}
