using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// The login path: which observations become sessions, how names are keyed,
/// and what reaches the plugin.
/// </summary>
public sealed class LoginPipelineTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "adidentity-tests", Guid.NewGuid().ToString("n"));

    [Fact]
    public async Task A_logon_becomes_a_session_and_a_push()
    {
        var h = NewHarness();

        await h.RunAsync(Logon("ivanov", "INTERNAL", "10.0.1.10"));

        var session = Assert.Single(h.Store.GetAll());
        Assert.Equal("login", session.Event);
        Assert.Equal(new[] { "Managers" }, session.Groups);
        Assert.Equal(session.Ip, Assert.Single(h.Plugin.Upserts).Ip);
    }

    [Fact]
    public async Task Only_monitored_groups_reach_the_plugin()
    {
        var h = NewHarness(
            options => options.MonitoredGroups.Add("Managers"),
            new FakeGroupResolver("Managers", "Domain Users", "Backup Operators"));

        await h.RunAsync(Logon("ivanov", "INTERNAL", "10.0.1.10"));

        Assert.Equal(new[] { "Managers" }, Assert.Single(h.Plugin.Upserts).Groups);
    }

    [Fact]
    public async Task The_group_filter_is_case_insensitive()
    {
        var h = NewHarness(
            options => options.MonitoredGroups.Add("managers"),
            new FakeGroupResolver("Managers"));

        await h.RunAsync(Logon("ivanov", "INTERNAL", "10.0.1.10"));

        Assert.Equal(new[] { "Managers" }, Assert.Single(h.Plugin.Upserts).Groups);
    }

    [Fact]
    public async Task A_user_in_no_monitored_group_still_becomes_a_session_with_no_groups()
    {
        // The plugin needs to know the address is claimed, otherwise a stale
        // entry from a previous holder could survive in some alias.
        var h = NewHarness(
            options => options.MonitoredGroups.Add("Managers"),
            new FakeGroupResolver("Domain Users"));

        await h.RunAsync(Logon("sidorov", "INTERNAL", "10.0.1.10"));

        Assert.Empty(Assert.Single(h.Plugin.Upserts).Groups);
    }

    [Fact]
    public async Task The_kerberos_realm_and_the_netbios_name_key_one_session()
    {
        // 4768 reports INTERNAL.LAB, 4624 reports INTERNAL (D19).
        var h = NewHarness();

        await h.RunAsync(
            Logon("ivanov", "INTERNAL.LAB", "10.0.1.10"),
            Logon("ivanov", "INTERNAL", "10.0.1.10", eventId: 4624, logonType: 10));

        var session = Assert.Single(h.Store.GetAll());
        Assert.Equal("INTERNAL", session.Domain);
    }

    [Fact]
    public async Task A_upn_style_account_name_keys_the_same_session()
    {
        var h = NewHarness();

        await h.RunAsync(
            Logon("ivanov", "INTERNAL", "10.0.1.10"),
            Logon("ivanov@INTERNAL.LAB", "INTERNAL", "10.0.1.10"));

        Assert.Equal("ivanov", Assert.Single(h.Store.GetAll()).User);
    }

    [Fact]
    public async Task A_down_level_account_name_keys_the_same_session()
    {
        var h = NewHarness();

        await h.RunAsync(
            Logon("ivanov", "INTERNAL", "10.0.1.10"),
            Logon(@"INTERNAL\ivanov", "INTERNAL", "10.0.1.10"));

        Assert.Equal("ivanov", Assert.Single(h.Store.GetAll()).User);
    }

    [Fact]
    public async Task A_second_user_takes_the_address_from_the_first()
    {
        // Criterion 9 of the pilot, as run in the lab with ivanov and petrov.
        var h = NewHarness(groups: new FakeGroupResolver("Developers"));
        await h.RunAsync(Logon("ivanov", "INTERNAL", "10.0.1.10"));

        await h.RunAsync(Logon("petrov", "INTERNAL", "10.0.1.10"));

        var session = Assert.Single(h.Store.GetAll());
        Assert.Equal("petrov", session.User);
    }

    [Theory]
    [InlineData("WINDOWS-TC0V6LD$")]
    [InlineData("ANONYMOUS LOGON")]
    public async Task Non_human_identities_never_become_sessions(string user)
    {
        var h = NewHarness();

        await h.RunAsync(Logon(user, "INTERNAL", "10.0.1.10"));

        Assert.Empty(h.Store.GetAll());
        Assert.Empty(h.Plugin.Upserts);
    }

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    [InlineData("-")]
    public async Task Local_addresses_never_become_sessions(string ip)
    {
        var h = NewHarness();

        await h.RunAsync(Logon("ivanov", "INTERNAL", ip));

        Assert.Empty(h.Store.GetAll());
    }

    [Fact]
    public async Task Expiry_is_computed_from_the_configured_ttl()
    {
        var h = NewHarness(options => options.SessionTtlSec = 28800);

        await h.RunAsync(Logon("ivanov", "INTERNAL", "10.0.1.10"));

        var expires = Assert.Single(h.Plugin.Upserts).ExpiresAt;
        Assert.NotNull(expires);
        Assert.InRange(
            expires!.Value - DateTimeOffset.UtcNow,
            TimeSpan.FromHours(8) - TimeSpan.FromMinutes(1),
            TimeSpan.FromHours(8));
    }

    [Fact]
    public async Task A_failing_event_does_not_stop_the_pipeline()
    {
        // One bad LDAP lookup must not end the loop for the whole shift.
        var h = NewHarness(groups: new ThrowingGroupResolver("ivanov"));

        await h.RunAsync(
            Logon("ivanov", "INTERNAL", "10.0.1.10"),
            Logon("petrov", "INTERNAL", "10.0.1.11"));

        Assert.Equal("petrov", Assert.Single(h.Store.GetAll()).User);
    }

    private static RawLogonEvent Logon(
        string user,
        string domain,
        string ip,
        int eventId = 4768,
        int? logonType = null) => new()
    {
        User = user,
        Domain = domain,
        Ip = ip,
        EventId = eventId,
        LogonType = logonType,
        Ts = DateTimeOffset.UtcNow,
        Dc = "DC01"
    };

    private Harness NewHarness(
        Action<AgentOptions>? configure = null,
        IGroupResolver? groups = null)
    {
        var options = new AgentOptions { SessionTtlSec = 900 };
        configure?.Invoke(options);

        return new Harness(
            options,
            groups ?? new FakeGroupResolver("Managers"),
            new FileSessionStore(
                NullLogger<FileSessionStore>.Instance,
                Path.Combine(_dir, "sessions.json")),
            new LoginMemory(
                NullLogger<LoginMemory>.Instance,
                Path.Combine(_dir, "login-memory.json")));
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private sealed class ThrowingGroupResolver : IGroupResolver
    {
        private readonly string _failFor;

        public ThrowingGroupResolver(string failFor) => _failFor = failFor;

        public Task<IReadOnlyList<string>> ResolveGroupsAsync(
            string user,
            string domain,
            CancellationToken cancellationToken)
        {
            if (string.Equals(user, _failFor, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("LDAP unavailable");
            }

            return Task.FromResult<IReadOnlyList<string>>(new[] { "Managers" });
        }
    }

    private sealed class Harness
    {
        private readonly AgentOptions _options;
        private readonly IGroupResolver _groups;
        private readonly LoginMemory _memory;

        public Harness(AgentOptions options, IGroupResolver groups, ISessionStore store, LoginMemory memory)
        {
            _options = options;
            _groups = groups;
            _memory = memory;
            Store = store;
        }

        public ISessionStore Store { get; }

        public FakePluginClient Plugin { get; } = new();

        public Task RunAsync(params RawLogonEvent[] events)
        {
            var pipeline = new SessionPipeline(
                new FakeEventCollector(events),
                _groups,
                Store,
                Plugin,
                _memory,
                Options.Create(_options),
                NullLogger<SessionPipeline>.Instance);

            return pipeline.RunAsync(CancellationToken.None);
        }
    }
}
