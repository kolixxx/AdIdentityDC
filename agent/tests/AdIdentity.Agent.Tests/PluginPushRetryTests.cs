using System.Net;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// Push retry rules (D6). Nothing replays a lost logon until the next one, so a
/// transient failure has to be retried - and a configuration error must not be,
/// or the agent hammers the firewall for nothing.
/// </summary>
public sealed class PluginPushRetryTests
{
    [Fact]
    public async Task A_first_attempt_that_succeeds_is_not_repeated()
    {
        var handler = new QueuedHandler(HttpStatusCode.OK);

        await NewClient(handler).UpsertAsync(Session(), CancellationToken.None);

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task A_server_error_is_retried_until_it_succeeds()
    {
        var handler = new QueuedHandler(
            HttpStatusCode.InternalServerError,
            HttpStatusCode.BadGateway,
            HttpStatusCode.OK);

        await NewClient(handler).UpsertAsync(Session(), CancellationToken.None);

        Assert.Equal(3, handler.Calls);
    }

    [Fact]
    public async Task A_network_failure_is_retried()
    {
        // This is the lab scenario: outbound block DC -> OPNsense.
        var handler = new QueuedHandler(HttpStatusCode.OK) { ThrowFirst = 2 };

        await NewClient(handler).UpsertAsync(Session(), CancellationToken.None);

        Assert.Equal(3, handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.RequestTimeout)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    public async Task Transient_statuses_are_retried(HttpStatusCode status)
    {
        var handler = new QueuedHandler(status, HttpStatusCode.OK);

        await NewClient(handler).UpsertAsync(Session(), CancellationToken.None);

        Assert.Equal(2, handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.Unauthorized)]
    [InlineData(HttpStatusCode.BadRequest)]
    [InlineData(HttpStatusCode.NotFound)]
    public async Task A_configuration_error_fails_on_the_first_attempt(HttpStatusCode status)
    {
        // A wrong token or a rejected payload will not fix itself; retrying
        // only delays the error and floods the log.
        var handler = new QueuedHandler(status);
        var client = NewClient(handler);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.UpsertAsync(Session(), CancellationToken.None));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Attempts_stop_at_the_configured_limit()
    {
        var handler = new QueuedHandler(HttpStatusCode.InternalServerError);
        var client = NewClient(handler, options => options.PushRetryCount = 3);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.UpsertAsync(Session(), CancellationToken.None));
        // One initial attempt plus three retries.
        Assert.Equal(4, handler.Calls);
    }

    [Fact]
    public async Task Retry_can_be_switched_off()
    {
        var handler = new QueuedHandler(HttpStatusCode.InternalServerError);
        var client = NewClient(handler, options => options.PushRetryCount = 0);

        await Assert.ThrowsAsync<HttpRequestException>(
            () => client.UpsertAsync(Session(), CancellationToken.None));
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task The_backoff_grows_between_attempts()
    {
        var handler = new QueuedHandler(
            HttpStatusCode.InternalServerError,
            HttpStatusCode.InternalServerError,
            HttpStatusCode.OK);
        var client = NewClient(handler, options => options.PushRetryDelayMs = 80);

        var started = DateTimeOffset.UtcNow;
        await client.UpsertAsync(Session(), CancellationToken.None);

        // 80 ms then 160 ms; without doubling this would finish in about 160 ms.
        Assert.True(DateTimeOffset.UtcNow - started >= TimeSpan.FromMilliseconds(240));
    }

    [Fact]
    public async Task Remove_is_retried_the_same_way()
    {
        var handler = new QueuedHandler(HttpStatusCode.InternalServerError, HttpStatusCode.OK);

        await NewClient(handler).RemoveAsync(
            "ivanov", "INTERNAL", "10.0.1.10", "logoff", CancellationToken.None);

        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task The_request_carries_the_shared_token_and_the_contract_fields()
    {
        var handler = new QueuedHandler(HttpStatusCode.OK);

        await NewClient(handler).UpsertAsync(Session(), CancellationToken.None);

        Assert.Equal("Bearer test-token", handler.LastAuthorization);
        Assert.Contains("\"user\":\"ivanov\"", handler.LastBody);
        Assert.Contains("\"ip\":\"10.0.1.10\"", handler.LastBody);
        Assert.Contains("\"event\":\"login\"", handler.LastBody);
        Assert.Contains("\"expires_at\":", handler.LastBody);
        Assert.Contains("/api/adidentity/session/upsert", handler.LastUrl);
    }

    private static PluginClient NewClient(QueuedHandler handler, Action<AgentOptions>? configure = null)
    {
        var options = new AgentOptions
        {
            PluginBaseUrl = "http://10.0.1.254",
            SharedToken = "test-token",
            PushRetryCount = 3,
            // Keep the suite fast; the doubling itself is asserted separately.
            PushRetryDelayMs = 1
        };
        configure?.Invoke(options);

        return new PluginClient(
            new HttpClient(handler),
            Options.Create(options),
            NullLogger<PluginClient>.Instance);
    }

    private static Session Session() => new()
    {
        User = "ivanov",
        Domain = "INTERNAL",
        Ip = "10.0.1.10",
        Groups = new[] { "Managers" },
        Event = "login",
        Ts = DateTimeOffset.UtcNow,
        Dc = "DC01",
        ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(15)
    };

    private sealed class QueuedHandler : HttpMessageHandler
    {
        private readonly Queue<HttpStatusCode> _responses;
        private readonly HttpStatusCode _last;

        public QueuedHandler(params HttpStatusCode[] responses)
        {
            _responses = new Queue<HttpStatusCode>(responses);
            _last = responses[^1];
        }

        /// <summary>Simulate a dropped connection on the first N attempts.</summary>
        public int ThrowFirst { get; init; }

        public int Calls { get; private set; }

        public string LastBody { get; private set; } = "";

        public string LastUrl { get; private set; } = "";

        public string LastAuthorization { get; private set; } = "";

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastUrl = request.RequestUri?.ToString() ?? "";
            LastAuthorization = request.Headers.Authorization?.ToString() ?? "";
            if (request.Content is not null)
            {
                LastBody = await request.Content.ReadAsStringAsync(cancellationToken);
            }

            if (Calls <= ThrowFirst)
            {
                throw new HttpRequestException("connection refused");
            }

            var status = _responses.Count > 0 ? _responses.Dequeue() : _last;
            return new HttpResponseMessage(status)
            {
                Content = new StringContent("{\"status\":\"ok\"}")
            };
        }
    }
}
