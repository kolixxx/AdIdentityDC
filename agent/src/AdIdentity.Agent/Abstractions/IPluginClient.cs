using AdIdentity.Agent.Models;

namespace AdIdentity.Agent.Abstractions;

public interface IPluginClient
{
    Task UpsertAsync(Session session, CancellationToken cancellationToken);
    Task RemoveAsync(string user, string domain, string ip, string reason, CancellationToken cancellationToken);
}
