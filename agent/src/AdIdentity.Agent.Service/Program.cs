using AdIdentity.Agent.Api;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Service;
using AdIdentity.Agent.Services;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "AdIdentity Agent";
});

builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));

var useStubCollector = builder.Configuration
    .GetSection(AgentOptions.SectionName)
    .GetSection("Events")
    .GetValue<bool>("UseStubCollector");

var useStubLdap = builder.Configuration
    .GetSection(AgentOptions.SectionName)
    .GetSection("Ldap")
    .GetValue<bool>("UseStubResolver");

builder.Services.AddSingleton<ISessionStore, FileSessionStore>();
if (useStubCollector)
{
    builder.Services.AddSingleton<IEventCollector, StubEventCollector>();
}
else
{
    builder.Services.AddSingleton<IEventCollector, SecurityEventLogCollector>();
}

if (useStubLdap)
{
    builder.Services.AddSingleton<IGroupResolver, StubGroupResolver>();
}
else
{
    builder.Services.AddSingleton<IGroupResolver, LdapGroupResolver>();
}

builder.Services.AddHttpClient<IPluginClient, PluginClient>();
builder.Services.AddSingleton<SessionPipeline>();
builder.Services.AddHostedService<AgentApiHost>();
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
await host.RunAsync();
