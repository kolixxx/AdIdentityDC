using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Dev/demo resolver. Returns configured monitored groups for any user.
/// Enabled via Ldap:UseStubResolver=true.
/// </summary>
public sealed class StubGroupResolver : IGroupResolver
{
    private readonly AgentOptions _options;
    private readonly ILogger<StubGroupResolver> _logger;

    public StubGroupResolver(IOptions<AgentOptions> options, ILogger<StubGroupResolver> logger)
    {
        _options = options.Value;
        _logger = logger;
    }

    public Task<IReadOnlyList<string>> ResolveGroupsAsync(string user, string domain, CancellationToken cancellationToken)
    {
        _logger.LogDebug("Stub LDAP resolve for {Domain}\\{User}", domain, user);
        IReadOnlyList<string> groups = _options.MonitoredGroups.ToList();
        return Task.FromResult(groups);
    }
}
