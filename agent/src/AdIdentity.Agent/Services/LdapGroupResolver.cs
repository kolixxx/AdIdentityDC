using System.Collections.Concurrent;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Text;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Resolves AD group membership over LDAP/LDAPS.
/// Default: nested groups via LDAP_MATCHING_RULE_IN_CHAIN; falls back to memberOf.
/// </summary>
public sealed class LdapGroupResolver : IGroupResolver, IDisposable
{
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);

    private readonly AgentOptions _options;
    private readonly ILogger<LdapGroupResolver> _logger;
    private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _connectionLock = new();
    private LdapConnection? _connection;

    public LdapGroupResolver(IOptions<AgentOptions> options, ILogger<LdapGroupResolver> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public async Task<IReadOnlyList<string>> ResolveGroupsAsync(
        string user,
        string domain,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(user))
        {
            return Array.Empty<string>();
        }

        var cacheKey = $"{domain}\\{user}";
        var cacheSeconds = Math.Max(0, _options.Ldap.CacheSeconds);
        if (cacheSeconds > 0 &&
            _cache.TryGetValue(cacheKey, out var cached) &&
            cached.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return cached.Groups;
        }

        // DirectoryServices.Protocols is sync; offload to thread pool.
        var groups = await Task.Run(
            () => ResolveGroupsCore(user, domain),
            cancellationToken).ConfigureAwait(false);

        if (cacheSeconds > 0)
        {
            _cache[cacheKey] = new CacheEntry(groups, DateTimeOffset.UtcNow.AddSeconds(cacheSeconds));
        }

        return groups;
    }

    private IReadOnlyList<string> ResolveGroupsCore(string user, string domain)
    {
        var ldap = _options.Ldap;
        if (string.IsNullOrWhiteSpace(ldap.Host) || string.IsNullOrWhiteSpace(ldap.BaseDn))
        {
            _logger.LogWarning("LDAP Host/BaseDn not configured; returning empty groups for {User}", user);
            return Array.Empty<string>();
        }

        try
        {
            var connection = GetConnection();
            var userDn = FindUserDn(connection, user, domain);
            if (userDn is null)
            {
                _logger.LogWarning("LDAP user not found: {Domain}\\{User}", domain, user);
                return Array.Empty<string>();
            }

            IReadOnlyList<string> groups = ldap.UseNestedGroups
                ? ResolveNestedGroups(connection, userDn)
                : ResolveMemberOf(connection, userDn);

            _logger.LogDebug(
                "LDAP groups for {Domain}\\{User}: {Count}",
                domain,
                user,
                groups.Count);

            return groups;
        }
        catch (Exception ex)
        {
            // Drop cached connection so next call reconnects.
            ResetConnection();
            _logger.LogError(ex, "LDAP resolve failed for {Domain}\\{User}", domain, user);
            throw;
        }
    }

    private LdapConnection GetConnection()
    {
        lock (_connectionLock)
        {
            if (_connection is not null)
            {
                return _connection;
            }

            var ldap = _options.Ldap;
            var identifier = new LdapDirectoryIdentifier(ldap.Host, ldap.Port, fullyQualifiedDnsHostName: false, connectionless: false);
            var connection = new LdapConnection(identifier)
            {
                Timeout = ConnectTimeout,
                AuthType = string.IsNullOrWhiteSpace(ldap.BindDn) ? AuthType.Negotiate : AuthType.Basic
            };

            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.SecureSocketLayer = ldap.UseSsl;
            if (ldap.IgnoreSslErrors)
            {
                connection.SessionOptions.VerifyServerCertificate += (_, _) => true;
            }

            if (!string.IsNullOrWhiteSpace(ldap.BindDn))
            {
                connection.Credential = new NetworkCredential(ldap.BindDn, ldap.BindPassword);
            }

            connection.Bind();
            _connection = connection;
            _logger.LogInformation(
                "LDAP connected to {Host}:{Port} ssl={Ssl}",
                ldap.Host,
                ldap.Port,
                ldap.UseSsl);
            return connection;
        }
    }

    private void ResetConnection()
    {
        lock (_connectionLock)
        {
            try
            {
                _connection?.Dispose();
            }
            catch
            {
                // ignore
            }

            _connection = null;
        }
    }

    private string? FindUserDn(LdapConnection connection, string user, string domain)
    {
        var escapedUser = EscapeLdapFilter(user);
        // Prefer sAMAccountName; also try UPN when domain looks like DNS.
        var filter = domain.Contains('.', StringComparison.Ordinal)
            ? $"(&(objectCategory=person)(objectClass=user)(|(sAMAccountName={escapedUser})(userPrincipalName={escapedUser}@{EscapeLdapFilter(domain)})))"
            : $"(&(objectCategory=person)(objectClass=user)(sAMAccountName={escapedUser}))";

        var request = new SearchRequest(
            _options.Ldap.BaseDn,
            filter,
            SearchScope.Subtree,
            "distinguishedName");

        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count == 0)
        {
            return null;
        }

        return response.Entries[0].DistinguishedName;
    }

    private IReadOnlyList<string> ResolveNestedGroups(LdapConnection connection, string userDn)
    {
        var filter =
            $"(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={EscapeLdapFilter(userDn)}))";

        var request = new SearchRequest(
            _options.Ldap.BaseDn,
            filter,
            SearchScope.Subtree,
            "cn");

        var response = (SearchResponse)connection.SendRequest(request);
        var names = new List<string>(response.Entries.Count);
        foreach (SearchResultEntry entry in response.Entries)
        {
            var cn = GetFirstAttribute(entry, "cn") ?? ExtractCnFromDn(entry.DistinguishedName);
            if (!string.IsNullOrWhiteSpace(cn))
            {
                names.Add(cn);
            }
        }

        return names
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private IReadOnlyList<string> ResolveMemberOf(LdapConnection connection, string userDn)
    {
        var request = new SearchRequest(
            userDn,
            "(objectClass=*)",
            SearchScope.Base,
            "memberOf");

        var response = (SearchResponse)connection.SendRequest(request);
        if (response.Entries.Count == 0)
        {
            return Array.Empty<string>();
        }

        var entry = response.Entries[0];
        if (!entry.Attributes.Contains("memberOf"))
        {
            return Array.Empty<string>();
        }

        var names = new List<string>();
        foreach (var value in entry.Attributes["memberOf"].GetValues(typeof(string)))
        {
            if (value is string dn)
            {
                var cn = ExtractCnFromDn(dn);
                if (!string.IsNullOrWhiteSpace(cn))
                {
                    names.Add(cn!);
                }
            }
        }

        return names
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? GetFirstAttribute(SearchResultEntry entry, string name)
    {
        if (!entry.Attributes.Contains(name))
        {
            return null;
        }

        var values = entry.Attributes[name].GetValues(typeof(string));
        return values.Length > 0 ? values[0] as string : null;
    }

    private static string? ExtractCnFromDn(string? dn)
    {
        if (string.IsNullOrWhiteSpace(dn))
        {
            return null;
        }

        // CN=Managers,OU=Groups,DC=corp,DC=local
        foreach (var part in dn.Split(','))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
            {
                return trimmed[3..];
            }
        }

        return null;
    }

    /// <summary>
    /// Escape LDAP filter special characters per RFC 4515.
    /// </summary>
    private static string EscapeLdapFilter(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            switch (ch)
            {
                case '\\':
                    sb.Append("\\5c");
                    break;
                case '*':
                    sb.Append("\\2a");
                    break;
                case '(':
                    sb.Append("\\28");
                    break;
                case ')':
                    sb.Append("\\29");
                    break;
                case '\0':
                    sb.Append("\\00");
                    break;
                default:
                    sb.Append(ch);
                    break;
            }
        }

        return sb.ToString();
    }

    public void Dispose() => ResetConnection();

    private sealed record CacheEntry(IReadOnlyList<string> Groups, DateTimeOffset ExpiresAt);
}
