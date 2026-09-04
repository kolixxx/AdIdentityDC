using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace AdIdentity.Agent.Services;

/// <summary>
/// [D23 login-memory] Remembers where a user was last seen logging in, for longer
/// than a session lives. Lets an activity event (4769) restore a session that
/// already timed out, without letting activity alone invent a new user-to-IP
/// binding: a Kerberos delegation event carries the user's name with a server's
/// address, which will not match any remembered login.
///
/// This whole file exists only for D23. To drop the feature, set
/// AdIdentity:ActivityRecreateEnabled to false, or see PROJECT_STATE.md for the
/// full removal steps.
/// </summary>
public sealed class LoginMemory
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true
    };

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _gate = new();
    private readonly string _path;
    private readonly ILogger<LoginMemory> _logger;

    public LoginMemory(ILogger<LoginMemory> logger)
    {
        _logger = logger;
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "AdIdentity");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "login-memory.json");
        Load();
    }

    /// <summary>
    /// Record an address confirmed by a real logon event (4768/4624/4776).
    /// v1 keeps one address per user, matching "one user holds one active IP".
    /// </summary>
    public void Remember(string user, string domain, string ip, DateTimeOffset ts)
    {
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(ip))
        {
            return;
        }

        lock (_gate)
        {
            _entries[MakeKey(user, domain)] = new Entry
            {
                User = user,
                Domain = domain,
                Ip = ip,
                LastLoginAt = ts
            };
            Save();
        }
    }

    /// <summary>
    /// True when this exact user and address were seen logging in within the retention window.
    /// </summary>
    public bool Recall(string user, string domain, string ip, int retentionHours)
    {
        if (retentionHours <= 0)
        {
            return false;
        }

        lock (_gate)
        {
            Prune(retentionHours);
            return _entries.TryGetValue(MakeKey(user, domain), out var entry) &&
                   string.Equals(entry.Ip, ip, StringComparison.OrdinalIgnoreCase);
        }
    }

    private void Prune(int retentionHours)
    {
        var cutoff = DateTimeOffset.UtcNow.AddHours(-retentionHours);
        var stale = _entries
            .Where(kv => kv.Value.LastLoginAt <= cutoff)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in stale)
        {
            _entries.Remove(key);
        }

        if (stale.Count > 0)
        {
            Save();
        }
    }

    private void Load()
    {
        if (!File.Exists(_path))
        {
            return;
        }

        try
        {
            var payload = JsonSerializer.Deserialize<MemoryFile>(File.ReadAllText(_path), JsonOptions);
            foreach (var entry in payload?.Logins ?? new List<Entry>())
            {
                if (string.IsNullOrWhiteSpace(entry.User) || string.IsNullOrWhiteSpace(entry.Ip))
                {
                    continue;
                }

                _entries[MakeKey(entry.User, entry.Domain)] = entry;
            }

            _logger.LogInformation("Loaded {Count} remembered logins from {Path}", _entries.Count, _path);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load login memory from {Path}; starting empty", _path);
            _entries.Clear();
        }
    }

    private void Save()
    {
        try
        {
            var payload = new MemoryFile
            {
                UpdatedAt = DateTimeOffset.UtcNow,
                Logins = _entries.Values.ToList()
            };
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(payload, JsonOptions));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist login memory to {Path}", _path);
        }
    }

    private static string MakeKey(string user, string domain) => $"{domain}\\{user}";

    public sealed class Entry
    {
        public string User { get; set; } = "";
        public string Domain { get; set; } = "";
        public string Ip { get; set; } = "";
        public DateTimeOffset LastLoginAt { get; set; }
    }

    private sealed class MemoryFile
    {
        public DateTimeOffset? UpdatedAt { get; set; }
        public List<Entry> Logins { get; set; } = new();
    }
}
