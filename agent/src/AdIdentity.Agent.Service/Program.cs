using AdIdentity.Agent.Api;
using AdIdentity.Agent.Abstractions;
using AdIdentity.Agent.Models;
using AdIdentity.Agent.Service;
using AdIdentity.Agent.Services;
using Microsoft.Extensions.DependencyInjection;

// SCM starts the process with cwd = System32. Pin ContentRoot to the exe folder
// so appsettings.json next to the binary is always loaded.
var exeDir = AppContext.BaseDirectory;
Directory.SetCurrentDirectory(exeDir);
var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = exeDir
});
builder.Configuration.AddJsonFile(
    Path.Combine(exeDir, "appsettings.json"),
    optional: false,
    reloadOnChange: false);

builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.SectionName));

var section = builder.Configuration.GetSection(AgentOptions.SectionName);
var role = section.GetValue<AgentRole>("Role");
var useStubCollector = section.GetSection("Events").GetValue<bool>("UseStubCollector");
var useStubLdap = section.GetSection("Ldap").GetValue<bool>("UseStubResolver");

// One SCM name on every host. Behavior comes from Role in appsettings, not from
// the Windows service name (avoids Start-Service failures when Role was mis-read).
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "AdIdentityAgent";
});

switch (role)
{
    case AgentRole.Sensor:
        RegisterSensor(builder.Services, useStubCollector);
        break;
    case AgentRole.Collector:
        RegisterCollector(builder.Services, useStubLdap);
        break;
    default:
        RegisterStandalone(builder.Services, useStubCollector, useStubLdap);
        break;
}

var host = builder.Build();
var logger = host.Services.GetRequiredService<ILoggerFactory>().CreateLogger("AdIdentity.Startup");
logger.LogInformation("Starting AdIdentity with Role={Role}", role);
await host.RunAsync();

static void RegisterStandalone(IServiceCollection services, bool useStubCollector, bool useStubLdap)
{
    services.AddSingleton<ISessionStore, FileSessionStore>();
    if (useStubCollector)
    {
        services.AddSingleton<IEventCollector, StubEventCollector>();
    }
    else
    {
        services.AddSingleton<IEventCollector, SecurityEventLogCollector>();
    }

    RegisterLdap(services, useStubLdap);
    RegisterPluginClient(services);
    services.AddSingleton<LoginMemory>();
    services.AddSingleton<SessionPipeline>();
    services.AddHostedService<AgentApiHost>();
    services.AddHostedService<SessionReconciler>();
    services.AddHostedService<Worker>();
}

static void RegisterCollector(IServiceCollection services, bool useStubLdap)
{
    services.AddSingleton<ISessionStore, FileSessionStore>();
    services.AddSingleton<IngestEventBus>();
    services.AddSingleton<IEventCollector>(sp => sp.GetRequiredService<IngestEventBus>());
    RegisterLdap(services, useStubLdap);
    RegisterPluginClient(services);
    services.AddSingleton<LoginMemory>();
    services.AddSingleton<SessionPipeline>();
    services.AddHostedService(sp => new AgentApiHost(
        sp.GetRequiredService<ISessionStore>(),
        sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentOptions>>(),
        sp.GetRequiredService<ILogger<AgentApiHost>>(),
        sp.GetRequiredService<IngestEventBus>()));
    services.AddHostedService<SessionReconciler>();
    services.AddHostedService<Worker>();
}

static void RegisterSensor(IServiceCollection services, bool useStubCollector)
{
    if (useStubCollector)
    {
        services.AddSingleton<IEventCollector, StubEventCollector>();
    }
    else
    {
        services.AddSingleton<IEventCollector, SecurityEventLogCollector>();
    }

    services.AddHttpClient<CollectorIngestClient>();
    services.AddHostedService<SensorWorker>();
}

static void RegisterPluginClient(IServiceCollection services)
{
    services.AddHttpClient<IPluginClient, PluginClient>()
        .ConfigurePrimaryHttpMessageHandler(sp =>
        {
            var handler = new HttpClientHandler();
            if (sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<AgentOptions>>().Value.PluginIgnoreSslErrors)
            {
                handler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            return handler;
        });
}

static void RegisterLdap(IServiceCollection services, bool useStubLdap)
{
    if (useStubLdap)
    {
        services.AddSingleton<IGroupResolver, StubGroupResolver>();
    }
    else
    {
        services.AddSingleton<IGroupResolver, LdapGroupResolver>();
    }
}
