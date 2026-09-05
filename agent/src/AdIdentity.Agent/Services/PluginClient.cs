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
        var baseUri = new Uri(_options.PluginBaseUrl.TrimEnd('/') + "/");
        GuardTransport(baseUri, _options.AllowInsecureTransport, _logger);
        _http.BaseAddress = baseUri;
        _http.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", _options.SharedToken);
    }

    /// <summary>
    /// [D9] Every request carries the shared token in a header, and that token is
    /// enough to inject arbitrary sessions into the firewall. Sending it over plain
    /// HTTP to a remote host is therefore a credential leak, not a mere warning, so
    /// it takes a deliberate opt-in. Certificate validation itself is left to the
    /// platform default: nothing here disables it.
    /// </summary>
    internal static void GuardTransport(Uri baseUri, bool allowInsecure, ILogger logger)
    {
        if (baseUri.Scheme == Uri.UriSchemeHttps)
        {
            return;
        }

        if (baseUri.IsLoopback)
        {
            return;
        }

        if (!allowInsecure)
        {
            throw new InvalidOperationException(
                $"Refusing to push to {baseUri} over plain HTTP: the shared token would be " +
                "sent in clear text to a remote host. Use an https:// PluginBaseUrl, or set " +
                "AdIdentity:AllowInsecureTransport to true to accept this risk knowingly.");
        }

        logger.LogWarning(
            "Pushing to {BaseUrl} over plain HTTP because AllowInsecureTransport is set. " +
            "The shared token is readable by anyone on the network path.",
            baseUri);
    }

    public Task UpsertAsync(Session session, CancellationToken cancellationToken) =>
        PostWithRetryAsync(
            "api/adidentity/session/upsert",
            session.ToContractPayload(),
            "upsert",
            cancellationToken);

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
