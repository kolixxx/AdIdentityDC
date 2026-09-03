namespace AdIdentity.Agent.Models;

public sealed class AgentOptions
{
    public const string SectionName = "AdIdentity";

    public string PluginBaseUrl { get; set; } = "https://opnsense.local";
    public string SharedToken { get; set; } = "";
    /// <summary>
    /// HttpListener prefix host. Use "+" for all interfaces; "0.0.0.0" is not a valid prefix.
    /// </summary>
    public string ListenAddr { get; set; } = "+";
    public int ListenPort { get; set; } = 8443;
    public int SessionTtlSec { get; set; } = 28800;
    public List<string> MonitoredGroups { get; set; } = new();
    public LdapOptions Ldap { get; set; } = new();
    public EventFilterOptions Events { get; set; } = new();
}

public sealed class LdapOptions
{
    /// <summary>
    /// If true, use StubGroupResolver instead of real LDAP (dev/demo only).
    /// </summary>
    public bool UseStubResolver { get; set; } = false;

    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 636;
    public bool UseSsl { get; set; } = true;

    /// <summary>
    /// Lab-only: accept any LDAP TLS certificate. Keep false in production.
    /// </summary>
    public bool IgnoreSslErrors { get; set; } = false;

    public string BindDn { get; set; } = "";
    public string BindPassword { get; set; } = "";
    public string BaseDn { get; set; } = "";

    /// <summary>
    /// Resolve nested group membership via LDAP_MATCHING_RULE_IN_CHAIN.
    /// </summary>
    public bool UseNestedGroups { get; set; } = true;

    /// <summary>
    /// Cache user→groups lookups (seconds). 0 disables cache.
    /// </summary>
    public int CacheSeconds { get; set; } = 600;
}

public sealed class EventFilterOptions
{
    /// <summary>
    /// If true, do not read Security Event Log (dev/demo only).
    /// </summary>
    public bool UseStubCollector { get; set; } = false;

    public bool Accept4768 { get; set; } = true;
    public bool Accept4624 { get; set; } = true;
    public List<int> LogonTypes4624 { get; set; } = new() { 10 };
    public bool Accept4776 { get; set; } = false;
}
