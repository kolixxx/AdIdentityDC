namespace AdIdentity.Agent.Abstractions;

public interface IGroupResolver
{
    Task<IReadOnlyList<string>> ResolveGroupsAsync(string user, string domain, CancellationToken cancellationToken);

    /// <summary>
    /// False when Ldap.UserSearchBases is set and the account lies under none of
    /// them. Resolvers without a directory behind them accept every account.
    /// </summary>
    Task<bool> IsUserInScopeAsync(string user, string domain, CancellationToken cancellationToken) =>
        Task.FromResult(true);
}
