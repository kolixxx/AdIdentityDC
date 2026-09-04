using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// Behaviour of 4769 activity events in the pipeline: refresh of a live session
/// (D22) and restore of an expired one from login memory (D23).
/// </summary>
public sealed class ActivityRefreshTests : IDisposable
{
    private const string Client = "10.0.1.10";
    private const string FileServer = "10.0.1.50";

    private readonly string _dir = Path.Combine(Path.GetTempPath(), "adidentity-tests", Guid.NewGuid().ToString("n"));

    private LoginMemory NewMemory() =>
        new(NullLogger<LoginMemory>.Instance, Path.Combine(_dir, "login-memory.json"));

    [Fact]
    public async Task Activity_extends_a_live_session()
    {
        var harness = NewHarness(Login(Client), Activity(Client, afterSeconds: 120));

        await harness.RunAsync();

        var pushes = harness.Plugin.Upserts;
        Assert.Equal(2, pushes.Count);
        Assert.Equal("login", pushes[0].Event);
        Assert.Equal("refresh", pushes[1].Event);
        Assert.True(pushes[1].ExpiresAt >= pushes[0].ExpiresAt);
        // A live session already knows its groups; no reason to hit LDAP again.
        Assert.Equal(1, harness.Groups.Calls);
    }

    [Fact]
    public async Task Activity_does_not_move_a_session_to_another_address()
    {
        var harness = NewHarness(Login(Client), Activity(FileServer, afterSeconds: 120));

        await harness.RunAsync();

        var session = Assert.Single(harness.Store.GetAll());
        Assert.Equal(Client, session.Ip);
        Assert.Single(harness.Plugin.Upserts);
    }

    [Fact]
    public async Task Activity_within_the_minimum_interval_is_dropped()
    {
        var harness = NewHarness(Login(Client), Activity(Client, afterSeconds: 5));

        await harness.RunAsync();

        Assert.Single(harness.Plugin.Upserts);
    }

    // ---------------- [D23 login-memory] ----------------

    [Fact]
    public async Task Expired_session_is_restored_for_a_remembered_logon()
    {
        var harness = NewHarness(Login(Client));
        await harness.RunAsync();
        harness.Store.ExpireAll();
        Assert.Empty(harness.Store.GetAll());

        await harness.RunAsync(Activity(Client, afterSeconds: 3600));

        var restored = Assert.Single(harness.Store.GetAll());
        Assert.Equal(Client, restored.Ip);
        Assert.Equal("refresh", restored.Event);
        Assert.Contains("Managers", restored.Groups);
        Assert.True(restored.ExpiresAt > DateTimeOffset.UtcNow);
        Assert.Equal("refresh", harness.Plugin.Upserts[^1].Event);
    }

    [Fact]
    public async Task Delegation_from_a_service_address_cannot_create_a_session()
    {
        // A service requesting a ticket on the user's behalf reports the user's
        // name with its own address. That pair was never seen in a logon.
        var harness = NewHarness(Login(Client));
        await harness.RunAsync();
        harness.Store.ExpireAll();

        await harness.RunAsync(Activity(FileServer, afterSeconds: 3600));

        Assert.Empty(harness.Store.GetAll());
        Assert.Single(harness.Plugin.Upserts);
    }

    [Fact]
    public async Task Activity_without_any_remembered_logon_creates_nothing()
    {
        var harness = NewHarness();

        await harness.RunAsync(Activity(Client, afterSeconds: 0));

        Assert.Empty(harness.Store.GetAll());
        Assert.Empty(harness.Plugin.Upserts);
        Assert.Equal(0, harness.Groups.Calls);
    }

    [Fact]
    public async Task Restore_is_off_when_the_feature_flag_is_off()
    {
        // The documented rollback: back to plain TTL counted from logon.
        var harness = NewHarness(options => options.ActivityRecreateEnabled = false);
        await harness.RunAsync(Login(Client));
        harness.Store.ExpireAll();

        await harness.RunAsync(Activity(Client, afterSeconds: 3600));

        Assert.Empty(harness.Store.GetAll());
        Assert.Single(harness.Plugin.Upserts);
    }

    [Fact]
    public async Task Restore_stops_after_the_login_memory_window()
    {
        var harness = NewHarness(options => options.LoginMemoryHours = 1);
        await harness.RunAsync(Login(Client, at: DateTimeOffset.UtcNow.AddHours(-2)));
        harness.Store.ExpireAll();

        await harness.RunAsync(Activity(Client, afterSeconds: 0));

        Assert.Empty(harness.Store.GetAll());
    }

    [Fact]
    public async Task Restored_session_survives_a_service_restart()
    {
        var shared = Path.Combine(_dir, "login-memory.json");
        var first = NewHarness();
        await first.RunAsync(Login(Client));

        // New process: empty session store, login memory read back from disk.
        var second = NewHarness();
        Assert.Empty(second.Store.GetAll());

        await second.RunAsync(Activity(Client, afterSeconds: 0));

        Assert.Single(second.Store.GetAll());
        Assert.True(File.Exists(shared));
    }

    [Fact]
    public async Task Restore_matches_a_upn_style_account_name()
    {
        // 4768 reports "ivanov"/"INTERNAL.LAB", 4769 reports "ivanov@INTERNAL.LAB".
        var harness = NewHarness();
        await harness.RunAsync(new RawLogonEvent
        {
            User = "ivanov",
            Domain = "INTERNAL.LAB",
            Ip = Client,
            EventId = 4768,
            Ts = DateTimeOffset.UtcNow,
            Dc = "DC01"
        });
        harness.Store.ExpireAll();

        await harness.RunAsync(new RawLogonEvent
        {
            User = "ivanov@INTERNAL.LAB",
            Domain = "INTERNAL.LAB",
            Ip = Client,
            EventId = 4769,
            Ts = DateTimeOffset.UtcNow,
            Dc = "DC01"
        });

        var restored = Assert.Single(harness.Store.GetAll());
        Assert.Equal("ivanov", restored.User);
        Assert.Equal("INTERNAL", restored.Domain);
    }

    [Fact]
    public async Task Restored_session_honours_the_monitored_groups_filter()
    {
        var harness = NewHarness(
            options => options.MonitoredGroups.Add("Managers"),
            groups: new FakeGroupResolver("Managers", "Domain Users"));
        await harness.RunAsync(Login(Client));
        harness.Store.ExpireAll();

        await harness.RunAsync(Activity(Client, afterSeconds: 3600));

        var restored = Assert.Single(harness.Store.GetAll());
        Assert.Equal(new[] { "Managers" }, restored.Groups);
    }

    private static RawLogonEvent Login(string ip, DateTimeOffset? at = null) => new()
    {
        User = "ivanov",
        Domain = "INTERNAL",
        Ip = ip,
        EventId = 4768,
        Ts = at ?? DateTimeOffset.UtcNow,
        Dc = "DC01"
    };

    private static RawLogonEvent Activity(string ip, int afterSeconds) => new()
    {
        User = "ivanov@INTERNAL.LAB",
        Domain = "INTERNAL",
        Ip = ip,
        EventId = 4769,
        Ts = DateTimeOffset.UtcNow.AddSeconds(afterSeconds),
        Dc = "DC01"
    };

    private Harness NewHarness(params RawLogonEvent[] events) => NewHarness(_ => { }, events: events);

    private Harness NewHarness(
        Action<AgentOptions> configure,
        FakeGroupResolver? groups = null,
        params RawLogonEvent[] events)
    {
        var options = new AgentOptions
        {
            SessionTtlSec = 900,
            ActivityRefreshMinIntervalSec = 60,
            ActivityRecreateEnabled = true,
            LoginMemoryHours = 24
        };
        configure(options);

        return new Harness(options, groups ?? new FakeGroupResolver("Managers"), NewMemory(), events);
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private sealed class Harness
    {
        private readonly AgentOptions _options;
        private readonly LoginMemory _memory;
        private readonly RawLogonEvent[] _initialEvents;

        public Harness(
            AgentOptions options,
            FakeGroupResolver groups,
            LoginMemory memory,
            RawLogonEvent[] initialEvents)
        {
            _options = options;
            _memory = memory;
            _initialEvents = initialEvents;
            Groups = groups;
        }

        public FakeGroupResolver Groups { get; }

        public FakeSessionStore Store { get; } = new();

        public FakePluginClient Plugin { get; } = new();

        public Task RunAsync() => RunAsync(_initialEvents);

        public Task RunAsync(params RawLogonEvent[] events)
        {
            var pipeline = new SessionPipeline(
                new FakeEventCollector(events),
                Groups,
                Store,
                Plugin,
                _memory,
                Options.Create(_options),
                NullLogger<SessionPipeline>.Instance);

            return pipeline.RunAsync(CancellationToken.None);
        }
    }
}
