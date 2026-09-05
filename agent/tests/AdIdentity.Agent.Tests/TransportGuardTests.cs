using AdIdentity.Agent.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace AdIdentity.Agent.Tests;

/// <summary>
/// D9. The shared token is enough to inject any session into the firewall, and it
/// rides in a header on every push. So an unencrypted push to a remote host is a
/// credential leak, and the agent must refuse it unless told otherwise in writing.
/// </summary>
public sealed class TransportGuardTests
{
    [Fact]
    public void Https_is_accepted()
    {
        Guard("https://opnsense.corp.local", allowInsecure: false);
    }

    [Fact]
    public void Plain_http_to_a_remote_host_is_refused()
    {
        var ex = Assert.Throws<InvalidOperationException>(
            () => Guard("http://10.0.1.254", allowInsecure: false));

        // The message has to name the way out, or the operator only learns that
        // the service will not start.
        Assert.Contains("AllowInsecureTransport", ex.Message);
    }

    [Fact]
    public void Plain_http_is_allowed_once_it_is_opted_into()
    {
        Guard("http://10.0.1.254", allowInsecure: true);
    }

    [Theory]
    [InlineData("http://127.0.0.1")]
    [InlineData("http://localhost:8080")]
    [InlineData("http://[::1]")]
    public void Loopback_needs_no_opt_in(string url)
    {
        // Nothing leaves the machine, so there is no wire to sniff. Dev runs and
        // the SSH-tunnel setup must not need the insecure flag.
        Guard(url, allowInsecure: false);
    }

    private static void Guard(string baseUrl, bool allowInsecure) =>
        PluginClient.GuardTransport(
            new Uri(baseUrl.TrimEnd('/') + "/"),
            allowInsecure,
            NullLogger<PluginClient>.Instance);
}
