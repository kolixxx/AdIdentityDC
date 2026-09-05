using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// Accept/reject rules for Security events. These decide which observations
/// ever become identity state, so a wrong "yes" hands firewall access to the
/// wrong address.
/// </summary>
public sealed class EventParsingTests
{
    private static readonly DateTimeOffset When = new(2026, 9, 5, 8, 46, 0, TimeSpan.Zero);

    [Fact]
    public void A_successful_4768_is_accepted()
    {
        var ok = Parse(4768, out var parsed, new()
        {
            ["TargetUserName"] = "ivanov",
            ["TargetDomainName"] = "INTERNAL.LAB",
            ["IpAddress"] = "::ffff:10.0.1.10",
            ["Status"] = "0x0"
        });

        Assert.True(ok);
        Assert.Equal("ivanov", parsed!.User);
        Assert.Equal("INTERNAL.LAB", parsed.Domain);
        Assert.Equal(4768, parsed.EventId);
        Assert.Equal(When, parsed.Ts);
        Assert.Equal("DC01", parsed.Dc);
    }

    [Fact]
    public void The_ipv6_mapped_prefix_is_stripped()
    {
        // 4768/4769 report ::ffff:10.0.1.10 while 4624 reports 10.0.1.10; without
        // stripping, the same person keys two different sessions.
        Parse(4768, out var parsed, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "::ffff:10.0.1.10",
            ["Status"] = "0x0"
        });

        Assert.Equal("10.0.1.10", parsed!.Ip);
    }

    [Theory]
    [InlineData("0x6")]
    [InlineData("0x12")]
    [InlineData("0xC000006D")]
    public void A_failed_4768_is_rejected(string status)
    {
        Assert.False(Parse(4768, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10",
            ["Status"] = status
        }));
    }

    [Theory]
    [InlineData("0x0")]
    [InlineData("0x00000000")]
    [InlineData("0")]
    public void Every_spelling_of_success_is_accepted(string status)
    {
        Assert.True(Parse(4768, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10",
            ["Status"] = status
        }));
    }

    [Fact]
    public void A_computer_account_is_rejected()
    {
        // Machine tickets are constant background noise on a DC.
        Assert.False(Parse(4768, out _, new()
        {
            ["TargetUserName"] = "WINDOWS-TC0V6LD$",
            ["IpAddress"] = "10.0.1.10",
            ["Status"] = "0x0"
        }));
    }

    [Theory]
    [InlineData("ANONYMOUS LOGON")]
    [InlineData("SYSTEM")]
    [InlineData("LOCAL SERVICE")]
    [InlineData("NETWORK SERVICE")]
    public void Service_identities_are_rejected(string user)
    {
        Assert.False(Parse(4768, out _, new()
        {
            ["TargetUserName"] = user,
            ["IpAddress"] = "10.0.1.10",
            ["Status"] = "0x0"
        }));
    }

    [Theory]
    [InlineData("-")]
    [InlineData("::1")]
    [InlineData("127.0.0.1")]
    [InlineData("")]
    public void An_event_without_a_usable_address_is_rejected(string ip)
    {
        Assert.False(Parse(4768, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = ip,
            ["Status"] = "0x0"
        }));
    }

    [Fact]
    public void A_4769_carries_its_event_id_so_the_pipeline_treats_it_as_activity()
    {
        var ok = Parse(4769, out var parsed, new()
        {
            ["TargetUserName"] = "ivanov@INTERNAL.LAB",
            ["TargetDomainName"] = "INTERNAL.LAB",
            ["IpAddress"] = "::ffff:10.0.1.10",
            ["Status"] = "0x0"
        });

        Assert.True(ok);
        Assert.Equal(4769, parsed!.EventId);
        Assert.Equal("ivanov@INTERNAL.LAB", parsed.User);
    }

    [Fact]
    public void A_4624_of_an_allowed_logon_type_is_accepted()
    {
        var ok = Parse(4624, out var parsed, new()
        {
            ["TargetUserName"] = "ivanov",
            ["TargetDomainName"] = "INTERNAL",
            ["IpAddress"] = "10.0.1.10",
            ["LogonType"] = "10"
        });

        Assert.True(ok);
        Assert.Equal(10, parsed!.LogonType);
    }

    [Fact]
    public void A_4624_network_logon_is_rejected_by_the_type_filter()
    {
        // Type 3 fires for any SMB access to the DC. Accepting it lets a file
        // share touch create identity state, which is the noise D19 warns about.
        Assert.False(Parse(4624, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10",
            ["LogonType"] = "3"
        }));
    }

    [Fact]
    public void An_empty_logon_type_filter_accepts_any_type()
    {
        var ok = Parse(
            4624,
            out _,
            new()
            {
                ["TargetUserName"] = "ivanov",
                ["IpAddress"] = "10.0.1.10",
                ["LogonType"] = "3"
            },
            options => options.Events.LogonTypes4624.Clear());

        Assert.True(ok);
    }

    [Fact]
    public void A_4624_without_a_logon_type_is_rejected()
    {
        Assert.False(Parse(4624, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10"
        }));
    }

    [Fact]
    public void A_disabled_event_id_is_ignored_even_when_well_formed()
    {
        Assert.False(Parse(
            4769,
            out _,
            new()
            {
                ["TargetUserName"] = "ivanov",
                ["IpAddress"] = "10.0.1.10",
                ["Status"] = "0x0"
            },
            options => options.Events.Accept4769 = false));
    }

    [Fact]
    public void An_unrelated_event_id_is_ignored()
    {
        Assert.False(Parse(4625, out _, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10"
        }));
    }

    [Fact]
    public void A_4776_is_rejected_when_it_reports_a_workstation_instead_of_an_address()
    {
        // 4776 usually carries a NetBIOS name, which cannot be put in a pf table.
        Assert.False(Parse(
            4776,
            out _,
            new()
            {
                ["TargetUserName"] = "ivanov",
                ["IpAddress"] = "LOCAL-WINDOWS-02"
            },
            options => options.Events.Accept4776 = true));
    }

    [Fact]
    public void A_4776_with_a_real_address_is_accepted()
    {
        var ok = Parse(
            4776,
            out var parsed,
            new()
            {
                ["TargetUserName"] = "ivanov",
                ["IpAddress"] = "10.0.1.10"
            },
            options => options.Events.Accept4776 = true);

        Assert.True(ok);
        Assert.Equal(4776, parsed!.EventId);
    }

    [Fact]
    public void A_missing_domain_becomes_unknown_rather_than_empty()
    {
        Parse(4768, out var parsed, new()
        {
            ["TargetUserName"] = "ivanov",
            ["IpAddress"] = "10.0.1.10",
            ["Status"] = "0x0"
        });

        Assert.Equal("UNKNOWN", parsed!.Domain);
    }

    [Fact]
    public void Named_values_are_read_out_of_the_event_xml()
    {
        const string xml = """
            <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
              <System><EventID>4768</EventID></System>
              <EventData>
                <Data Name='TargetUserName'>ivanov</Data>
                <Data Name='TargetDomainName'>INTERNAL.LAB</Data>
                <Data Name='IpAddress'>::ffff:10.0.1.10</Data>
                <Data Name='Status'>0x0</Data>
                <Data>positional value without a name</Data>
              </EventData>
            </Event>
            """;

        var data = SecurityEventLogCollector.ParseEventDataXml(xml);

        Assert.Equal("ivanov", data["TargetUserName"]);
        Assert.Equal("::ffff:10.0.1.10", data["IpAddress"]);
        Assert.Equal(4, data.Count);
        // Lookups in the parser are case-insensitive.
        Assert.Equal("ivanov", data["targetusername"]);
    }

    private static bool Parse(
        int eventId,
        out RawLogonEvent? parsed,
        Dictionary<string, string> data,
        Action<AgentOptions>? configure = null)
    {
        var options = new AgentOptions();
        configure?.Invoke(options);

        var collector = new SecurityEventLogCollector(
            Options.Create(options),
            NullLogger<SecurityEventLogCollector>.Instance);

        return collector.TryParseValues(eventId, data, When, "DC01", out parsed);
    }
}
