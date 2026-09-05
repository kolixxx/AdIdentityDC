using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Services;

public sealed class PluginClient : IPluginClient
{
    private static readonly TimeSpan MaxBackoff = TimeSpan.FromSeconds(30);

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

    public Task UpsertAsync(Session session, CancellationToken cancellationToken)
    {
        var payload = new Dictionary<string, object?>
        {
            ["user"] = session.User,
            ["domain"] = session.Domain,
            ["ip"] = session.Ip,
            ["groups"] = session.Groups,
            ["event"] = session.Event,
            ["ts"] = IsoUtc.Format(session.Ts),
            ["dc"] = session.Dc,
            ["expires_at"] = session.ExpiresAt is null ? null : IsoUtc.Format(session.ExpiresAt.Value)
        };

        return PostWithRetryAsync("api/adidentity/session/upsert", payload, "upsert", cancellationToken);
    }

    public Task RemoveAsync(string user, string domain, string ip, string reason, CancellationToken cancellationToken)
    {
        var payload = new
        {
            user,
            domain,
            ip,
            reason
        };

        return PostWithRetryAsync("api/adidentity/session/remove", payload, "remove", cancellationToken);
    }

    /// <summary>
    /// Retry transient failures with exponential backoff. A single lost event would
    /// otherwise never reach the plugin, since nothing replays it until the next logon.
    /// Rejections caused by configuration (auth, bad payload) are not retried.
    /// </summary>
    private async Task PostWithRetryAsync(
        string path,
        object payload,
        string operation,
        CancellationToken cancellationToken)
    {
        var attempts = 1 + Math.Max(0, _options.PushRetryCount);
        var delay = TimeSpan.FromMilliseconds(Math.Max(1, _options.PushRetryDelayMs));

        for (var attempt = 1; ; attempt++)
        {
            // Raised for a status we must not retry. It is thrown below, outside
            // the try, because the catch filter treats every HttpRequestException
            // as transient and would otherwise swallow this one back into the loop.
            HttpRequestException? fatal = null;

            try
            {
                using var response = await _http.PostAsJsonAsync(path, payload, cancellationToken);
                if (response.IsSuccessStatusCode)
                {
                    if (attempt > 1)
                    {
                        _logger.LogInformation(
                            "Plugin {Operation} succeeded on attempt {Attempt}", operation, attempt);
                    }

                    return;
                }

                var body = await response.Content.ReadAsStringAsync(cancellationToken);
                var status = (int)response.StatusCode;
                if (!IsTransient(response.StatusCode) || attempt >= attempts)
                {
                    _logger.LogError(
                        "Plugin {Operation} failed: {Status} {Body}", operation, status, body);
                    fatal = new HttpRequestException(
                        $"Plugin {operation} failed with status {status}.",
                        inner: null,
                        response.StatusCode);
                }
                else
                {
                    _logger.LogWarning(
                        "Plugin {Operation} attempt {Attempt}/{Attempts} got {Status}; retrying in {Delay}",
                        operation, attempt, attempts, status, delay);
                }
            }
            catch (Exception ex) when (IsTransient(ex) && attempt < attempts)
            {
                _logger.LogWarning(
                    ex,
                    "Plugin {Operation} attempt {Attempt}/{Attempts} failed; retrying in {Delay}",
                    operation, attempt, attempts, delay);
            }

            if (fatal is not null)
            {
                throw fatal;
            }

            await Task.Delay(delay, cancellationToken);
            var next = delay * 2;
            delay = next > MaxBackoff ? MaxBackoff : next;
        }
    }

    private static bool IsTransient(HttpStatusCode status) =>
        (int)status >= 500 ||
        status == HttpStatusCode.RequestTimeout ||
        status == HttpStatusCode.TooManyRequests;

    private static bool IsTransient(Exception ex) =>
        ex is HttpRequestException ||
        ex is TimeoutException ||
        (ex is TaskCanceledException tce && tce.InnerException is TimeoutException);
}
