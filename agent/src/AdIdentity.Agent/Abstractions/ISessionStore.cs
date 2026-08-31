using AdIdentity.Agent.Models;

namespace AdIdentity.Agent.Abstractions;

public interface ISessionStore
{
    IReadOnlyCollection<Session> GetAll();
    Session? Upsert(Session session);
    bool Remove(string user, string domain, string ip);
    int Count { get; }
}
