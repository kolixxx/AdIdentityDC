using System.Net.Http.Headers;
using System.Net.Http.Json;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

/// <summary>
/// Sensor → Collector: POST /api/v1/ingest/event with the same Bearer token.
/// </summary>
public sealed class CollectorIngestClient
{
    private readonly HttpClient _http;
    private readonly ILogger<CollectorIngestClient> _logger;

    public CollectorIngestClient(
        HttpClient http,
        IOptions<AgentOptions> options,
        ILogger<CollectorIngestClient> logger)
    {
        _http = http;
        _logger = logger;
        var opts = options.Value;
        if (string.IsNullOrWhiteSpace(opts.CollectorBaseUrl))
        {
            throw new InvalidOperationException(
                "AdIdentity:CollectorBaseUrl is required when Role=Sensor.");
        }

        var baseUri = new Uri(opts.CollectorBaseUrl.TrimEnd('/') + "/");
        PluginClient.GuardTransport(baseUri, opts.AllowInsecureTransport, logger);
        _http.BaseAddress = baseUri;
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", opts.SharedToken);
    }

    public async Task ForwardAsync(RawLogonEvent raw, CancellationToken cancellationToken)
    {
        var payload = new
        {
            user = raw.User,
            domain = raw.Domain,
            ip = raw.Ip,
            eventId = raw.EventId,
            logonType = raw.LogonType,
            ts = IsoUtc.Format(raw.Ts),
            dc = raw.Dc
        };

        using var response = await _http.PostAsJsonAsync(
            "api/v1/ingest/event",
            payload,
            cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync(cancellationToken);
            _logger.LogWarning(
                "Collector ingest failed HTTP {Status} for {Domain}\\{User} {Ip} event={EventId}: {Body}",
                (int)response.StatusCode,
                raw.Domain,
                raw.User,
                raw.Ip,
                raw.EventId,
                body);
            response.EnsureSuccessStatusCode();
        }
    }
}
