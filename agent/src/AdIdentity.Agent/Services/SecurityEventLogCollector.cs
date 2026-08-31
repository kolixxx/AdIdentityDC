using System.Diagnostics.Eventing.Reader;
using System.Threading.Channels;
using System.Xml.Linq;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Reads Windows Security Event Log and emits user+ip observations.
/// Primary: 4768 (Kerberos TGT). Optional: 4624 (filtered logon types), 4776 (NTLM).
/// </summary>
public sealed class SecurityEventLogCollector : IEventCollector
{
    private readonly AgentOptions _options;
    private readonly ILogger<SecurityEventLogCollector> _logger;

    public SecurityEventLogCollector(
        IOptions<AgentOptions> options,
        ILogger<SecurityEventLogCollector> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async IAsyncEnumerable<RawLogonEvent> WatchAsync(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        var query = BuildQuery(_options.Events);
        if (query is null)
        {
            _logger.LogError("No Security event IDs enabled in configuration; collector idle");
            yield break;
        }

        var channel = Channel.CreateUnbounded<RawLogonEvent>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

        EventLogWatcher? watcher = null;
        try
        {
            var eventQuery = new EventLogQuery("Security", PathType.LogName, query)
            {
                ReverseDirection = false
            };

            try
            {
                watcher = new EventLogWatcher(eventQuery);
                watcher.EventRecordWritten += (_, args) =>
                {
                    if (args.EventRecord is null)
                    {
                        if (args.EventException is not null)
                        {
                            _logger.LogWarning(args.EventException, "Security Event Log watcher error");
                        }

                        return;
                    }

                    try
                    {
                        using var record = args.EventRecord;
                        if (TryParse(record, out var parsed) && parsed is not null)
                        {
                            channel.Writer.TryWrite(parsed);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Failed to parse Security event");
                    }
                };

                watcher.Enabled = true;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Cannot open Security Event Log. Run elevated on a Domain Controller with relevant audit policy enabled.");
                yield break;
            }

            _logger.LogInformation("Security Event Log collector started with query: {Query}", query);

            cancellationToken.Register(() => channel.Writer.TryComplete());

            await foreach (var item in channel.Reader.ReadAllAsync(cancellationToken))
            {
                yield return item;
            }
        }
        finally
        {
            if (watcher is not null)
            {
                try
                {
                    watcher.Enabled = false;
                    watcher.Dispose();
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Error disposing EventLogWatcher");
                }
            }

            channel.Writer.TryComplete();
        }
    }

    internal bool TryParse(EventRecord record, out RawLogonEvent? parsed)
    {
        parsed = null;
        var eventId = (int)record.Id;
        var data = ReadEventData(record);

        return eventId switch
        {
            4768 when _options.Events.Accept4768 => TryParse4768(record, data, out parsed),
            4624 when _options.Events.Accept4624 => TryParse4624(record, data, out parsed),
            4776 when _options.Events.Accept4776 => TryParse4776(record, data, out parsed),
            _ => false
        };
    }

    private bool TryParse4768(EventRecord record, IReadOnlyDictionary<string, string> data, out RawLogonEvent? parsed)
    {
        parsed = null;

        // 0x0 = success
        if (data.TryGetValue("Status", out var status) &&
            !IsSuccessStatus(status))
        {
            return false;
        }

        var user = Get(data, "TargetUserName", "AccountName");
        var domain = Get(data, "TargetDomainName", "AccountDomain");
        var ip = NormalizeIp(Get(data, "IpAddress", "ClientAddress"));

        if (!IsUsefulIdentity(user, ip))
        {
            return false;
        }

        parsed = new RawLogonEvent
        {
            User = user!,
            Domain = string.IsNullOrWhiteSpace(domain) ? "UNKNOWN" : domain!,
            Ip = ip!,
            EventId = 4768,
            LogonType = null,
            Ts = record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            Dc = record.MachineName ?? Environment.MachineName
        };
        return true;
    }

    private bool TryParse4624(EventRecord record, IReadOnlyDictionary<string, string> data, out RawLogonEvent? parsed)
    {
        parsed = null;

        var logonTypeRaw = Get(data, "LogonType");
        if (!int.TryParse(logonTypeRaw, out var logonType))
        {
            return false;
        }

        if (_options.Events.LogonTypes4624.Count > 0 &&
            !_options.Events.LogonTypes4624.Contains(logonType))
        {
            return false;
        }

        var user = Get(data, "TargetUserName");
        var domain = Get(data, "TargetDomainName");
        var ip = NormalizeIp(Get(data, "IpAddress", "SourceNetworkAddress"));

        if (!IsUsefulIdentity(user, ip))
        {
            return false;
        }

        parsed = new RawLogonEvent
        {
            User = user!,
            Domain = string.IsNullOrWhiteSpace(domain) ? "UNKNOWN" : domain!,
            Ip = ip!,
            EventId = 4624,
            LogonType = logonType,
            Ts = record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            Dc = record.MachineName ?? Environment.MachineName
        };
        return true;
    }

    private bool TryParse4776(EventRecord record, IReadOnlyDictionary<string, string> data, out RawLogonEvent? parsed)
    {
        parsed = null;

        // 4776 often has workstation name, not a reliable IP. Accept only when IP-like value exists.
        var user = Get(data, "TargetUserName");
        var domain = Get(data, "TargetDomainName") ?? "UNKNOWN";
        var ip = NormalizeIp(Get(data, "IpAddress", "SourceNetworkAddress"));

        // 4776 often lacks a client IP; skip unless an IP is present.
        if (!IsUsefulIdentity(user, ip) || !LooksLikeIp(ip!))
        {
            return false;
        }

        parsed = new RawLogonEvent
        {
            User = user!,
            Domain = domain,
            Ip = ip!,
            EventId = 4776,
            LogonType = null,
            Ts = record.TimeCreated?.ToUniversalTime() ?? DateTimeOffset.UtcNow,
            Dc = record.MachineName ?? Environment.MachineName
        };
        return true;
    }

    private static string? BuildQuery(EventFilterOptions events)
    {
        var ids = new List<int>();
        if (events.Accept4768) ids.Add(4768);
        if (events.Accept4624) ids.Add(4624);
        if (events.Accept4776) ids.Add(4776);
        if (ids.Count == 0)
        {
            return null;
        }

        var idExpr = string.Join(" or ", ids.Select(id => $"EventID={id}"));
        return $"*[System[({idExpr})]]";
    }

    private static Dictionary<string, string> ReadEventData(EventRecord record)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var xml = record.ToXml();
            var doc = XDocument.Parse(xml);
            XNamespace ns = "http://schemas.microsoft.com/win/2004/08/events/event";
            foreach (var node in doc.Descendants(ns + "Data"))
            {
                var name = (string?)node.Attribute("Name");
                if (string.IsNullOrWhiteSpace(name))
                {
                    continue;
                }

                map[name] = (node.Value ?? string.Empty).Trim();
            }
        }
        catch
        {
            // Fall back to positional properties if XML parse fails.
            if (record.Properties is not null)
            {
                for (var i = 0; i < record.Properties.Count; i++)
                {
                    map[$"Property{i}"] = record.Properties[i]?.Value?.ToString()?.Trim() ?? string.Empty;
                }
            }
        }

        return map;
    }

    private static string? Get(IReadOnlyDictionary<string, string> data, params string[] keys)
    {
        foreach (var key in keys)
        {
            if (data.TryGetValue(key, out var value) && !string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return null;
    }

    private static bool IsUsefulIdentity(string? user, string? ip)
    {
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(ip))
        {
            return false;
        }

        if (user.EndsWith('$') ||
            user.Equals("ANONYMOUS LOGON", StringComparison.OrdinalIgnoreCase) ||
            user.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
            user.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
            user.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (ip is "-" or "::1" or "127.0.0.1")
        {
            return false;
        }

        // Some events prefix IPv6-mapped values like "::ffff:10.0.0.1"
        return true;
    }

    private static string? NormalizeIp(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var ip = value.Trim();
        const string mapped = "::ffff:";
        if (ip.StartsWith(mapped, StringComparison.OrdinalIgnoreCase))
        {
            ip = ip[mapped.Length..];
        }

        return ip;
    }

    private static bool LooksLikeIp(string value)
    {
        return System.Net.IPAddress.TryParse(value, out _);
    }

    private static bool IsSuccessStatus(string status)
    {
        var s = status.Trim();
        return s is "0x0" or "0x00000000" or "0";
    }
}
