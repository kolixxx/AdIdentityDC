using AdIdentity.Agent.Models;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// Session store rules the lab verified by hand: one address belongs to one
/// user (D1), expired sessions disappear, and the snapshot survives a restart (D8).
/// </summary>
public sealed class SessionStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "adidentity-tests", Guid.NewGuid().ToString("n"));

    private FileSessionStore NewStore() =>
        new(NullLogger<FileSessionStore>.Instance, Path.Combine(_dir, "sessions.json"));

    [Fact]
    public void A_new_user_on_the_same_address_evicts_the_previous_one()
    {
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers"));

        store.Upsert(Session("petrov", "10.0.1.10", "Developers"));

        var held = Assert.Single(store.GetAll());
        Assert.Equal("petrov", held.User);
        Assert.Equal(new[] { "Developers" }, held.Groups);
    }

    [Fact]
    public void Eviction_ignores_a_still_valid_ttl_on_the_previous_session()
    {
        // The point of D1: the address is taken back on the new logon, not when
        // the old session finally times out.
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers", ttl: TimeSpan.FromHours(8)));

        store.Upsert(Session("petrov", "10.0.1.10", "Developers"));

        Assert.DoesNotContain(store.GetAll(), s => s.User == "ivanov");
    }

    [Fact]
    public void Users_on_different_addresses_coexist()
    {
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers"));
        store.Upsert(Session("petrov", "10.0.1.11", "Developers"));

        Assert.Equal(2, store.Count);
    }

    [Fact]
    public void The_same_user_moving_to_a_new_address_keeps_one_session()
    {
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers"));

        store.Upsert(Session("ivanov", "10.0.1.20", "Managers"));

        var held = Assert.Single(store.GetAll());
        Assert.Equal("10.0.1.20", held.Ip);
    }

    [Fact]
    public void Expired_sessions_disappear_from_reads()
    {
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers", ttl: TimeSpan.FromSeconds(-1)));

        Assert.Empty(store.GetAll());
        Assert.Equal(0, store.Count);
    }

    [Fact]
    public void A_session_without_an_expiry_is_kept()
    {
        // TTL is applied by the plugin as well; a missing value must not be
        // treated as "already expired" here.
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers", withoutExpiry: true));

        Assert.Single(store.GetAll());
    }

    [Fact]
    public void Remove_requires_the_address_to_match()
    {
        var store = NewStore();
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers"));

        Assert.False(store.Remove("ivanov", "INTERNAL", "10.0.1.99"));
        Assert.True(store.Remove("ivanov", "INTERNAL", "10.0.1.10"));
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public void Remove_of_an_unknown_session_reports_false()
    {
        Assert.False(NewStore().Remove("nobody", "INTERNAL", "10.0.1.10"));
    }

    [Fact]
    public void Sessions_survive_a_service_restart()
    {
        NewStore().Upsert(Session("ivanov", "10.0.1.10", "Managers", ttl: TimeSpan.FromHours(8)));

        // Fresh instance over the same file, as after a service restart (D8).
        var reloaded = Assert.Single(NewStore().GetAll());
        Assert.Equal("ivanov", reloaded.User);
        Assert.Equal(new[] { "Managers" }, reloaded.Groups);
    }

    [Fact]
    public void Expired_sessions_are_dropped_while_loading()
    {
        NewStore().Upsert(Session("ivanov", "10.0.1.10", "Managers", ttl: TimeSpan.FromSeconds(-1)));

        Assert.Empty(NewStore().GetAll());
    }

    [Fact]
    public void A_corrupt_snapshot_does_not_stop_the_agent()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, "sessions.json"), "{ not json");

        var store = NewStore();

        Assert.Empty(store.GetAll());
        store.Upsert(Session("ivanov", "10.0.1.10", "Managers"));
        Assert.Single(store.GetAll());
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir))
        {
            Directory.Delete(_dir, recursive: true);
        }
    }

    private static Session Session(
        string user,
        string ip,
        string group,
        TimeSpan? ttl = null,
        bool withoutExpiry = false)
    {
        DateTimeOffset? expires = withoutExpiry
            ? null
            : DateTimeOffset.UtcNow.Add(ttl ?? TimeSpan.FromMinutes(15));

        return new Session
        {
            User = user,
            Domain = "INTERNAL",
            Ip = ip,
            Groups = new[] { group },
            Event = "login",
            Ts = DateTimeOffset.UtcNow,
            Dc = "DC01",
            ExpiresAt = expires
        };
    }
}
