using System.Net.Http.Headers;
using System.Net.Http.Json;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

public sealed class PluginClient : IPluginClient
{
    private readonly HttpClient _http;
    private readonly AgentOptions _options;
    private readonly ILogger<PluginClient> _logger;

    public PluginClient(HttpClient http, IOptions<AgentOptions> options, ILogger<PluginClient> logger)
    {
        _http = http;
        _options = options.Value;
        _logger = logger;
        _http.BaseAddress = new Uri(_options.PluginBaseUrl.TrimEnd('/') + "/");
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _options.SharedToken);
    }

    public async Task UpsertAsync(Session session, CancellationToken cancellationToken)
    {
        var payload = new Dictionary<string, object?>
        {
            ["user"] = session.User,
            ["domain"] = session.Domain,
            ["ip"] = session.Ip,
            ["groups"] = session.Groups,
            ["event"] = session.Event,
            ["ts"] = session.Ts.UtcDateTime.ToString("o"),
            ["dc"] = session.Dc,
            ["expires_at"] = session.ExpiresAt?.UtcDateTime.ToString("o")
        };

        using var response = await _http.PostAsJsonAsync(
            "api/adidentity/session/upsert",
            payload,
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("Plugin upsert failed: {Status} {Body}", (int)response.StatusCode, body);
            response.EnsureSuccessStatusCode();
        }
    }

    public async Task RemoveAsync(string user, string domain, string ip, string reason, CancellationToken cancellationToken)
    {
        var payload = new
        {
            user,
            domain,
            ip,
            reason
        };

        using var response = await _http.PostAsJsonAsync(
            "api/adidentity/session/remove",
            payload,
            cancellationToken);

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogError("Plugin remove failed: {Status} {Body}", (int)response.StatusCode, body);
            response.EnsureSuccessStatusCode();
        }
    }
}
