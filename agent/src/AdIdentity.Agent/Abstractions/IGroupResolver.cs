namespace AdIdentity.Agent.Abstractions;

public interface IGroupResolver
{
    Task<IReadOnlyList<string>> ResolveGroupsAsync(string user, string domain, CancellationToken cancellationToken);
}
