using System.Net;
using System.Text;
using System.Text.Json;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AdIdentity.Agent.Api;

/// <summary>
/// Minimal HTTP listener for Agent API: /api/v1/health and /api/v1/sessions.
/// </summary>
public sealed class AgentApiHost : BackgroundService
{
    private readonly ISessionStore _store;
    private readonly AgentOptions _options;
    private readonly ILogger<AgentApiHost> _logger;
    private HttpListener? _listener;

    public AgentApiHost(ISessionStore store, IOptions<AgentOptions> options, ILogger<AgentApiHost> logger)
    {
        _store = store;
        _options = options.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var prefix = $"http://{_options.ListenAddr}:{_options.ListenPort}/";
        _listener = new HttpListener();
        _listener.Prefixes.Add(prefix);
        try
        {
            _listener.Start();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to start Agent API on {Prefix}. On Windows, URL ACL may be required.", prefix);
            return;
        }

        _logger.LogInformation("Agent API listening on {Prefix}", prefix);

        while (!stoppingToken.IsCancellationRequested)
        {
            var contextTask = _listener.GetContextAsync();
            var completed = await Task.WhenAny(contextTask, Task.Delay(Timeout.Infinite, stoppingToken));
            if (completed != contextTask)
            {
                break;
            }

            _ = Task.Run(() => HandleRequestAsync(contextTask.Result, stoppingToken), stoppingToken);
        }
    }

    private async Task HandleRequestAsync(HttpListenerContext context, CancellationToken cancellationToken)
    {
        try
        {
            if (!Authorize(context.Request))
            {
                context.Response.StatusCode = 401;
                await WriteJsonAsync(context.Response, new { status = "failed", message = "unauthorized" }, cancellationToken);
                return;
            }

            var path = context.Request.Url?.AbsolutePath.TrimEnd('/') ?? "";
            if (context.Request.HttpMethod == "GET" && path.Equals("/api/v1/health", StringComparison.OrdinalIgnoreCase))
            {
                await WriteJsonAsync(context.Response, new
                {
                    status = "ok",
                    version = "0.1.0",
                    sessions = _store.Count
                }, cancellationToken);
                return;
            }

            if (context.Request.HttpMethod == "GET" && path.Equals("/api/v1/sessions", StringComparison.OrdinalIgnoreCase))
            {
                var sessions = _store.GetAll().Select(s => new
                {
                    user = s.User,
                    domain = s.Domain,
                    ip = s.Ip,
                    groups = s.Groups,
                    @event = s.Event,
                    ts = IsoUtc.Format(s.Ts),
                    dc = s.Dc,
                    expires_at = s.ExpiresAt is null ? null : IsoUtc.Format(s.ExpiresAt.Value)
                });
                await WriteJsonAsync(context.Response, new { sessions }, cancellationToken);
                return;
            }

            context.Response.StatusCode = 404;
            await WriteJsonAsync(context.Response, new { status = "failed", message = "not found" }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Agent API request failed");
            try
            {
                context.Response.StatusCode = 500;
                await WriteJsonAsync(context.Response, new { status = "failed" }, cancellationToken);
            }
            catch
            {
                // ignore
            }
        }
        finally
        {
            context.Response.OutputStream.Close();
        }
    }

    private bool Authorize(HttpListenerRequest request)
    {
        var expected = _options.SharedToken;
        if (string.IsNullOrEmpty(expected))
        {
            return false;
        }

        var header = request.Headers["Authorization"];
        if (header is null || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var token = header["Bearer ".Length..].Trim();
        return CryptographicEquals(expected, token);
    }

    private static bool CryptographicEquals(string a, string b)
    {
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        if (ba.Length != bb.Length)
        {
            return false;
        }

        var diff = 0;
        for (var i = 0; i < ba.Length; i++)
        {
            diff |= ba[i] ^ bb[i];
        }

        return diff == 0;
    }

    private static async Task WriteJsonAsync(HttpListenerResponse response, object payload, CancellationToken cancellationToken)
    {
        response.ContentType = "application/json";
        var json = JsonSerializer.Serialize(payload);
        var bytes = Encoding.UTF8.GetBytes(json);
        response.ContentLength64 = bytes.Length;
        await response.OutputStream.WriteAsync(bytes, cancellationToken);
    }

    public override void Dispose()
    {
        if (_listener is not null)
        {
            if (_listener.IsListening)
            {
                _listener.Stop();
            }

            _listener.Close();
        }

        base.Dispose();
    }
}
