namespace Mesch.Authzn;

/// <summary>
/// Default implementation of the authorization engine that evaluates permissions against roles and assignments.
/// </summary>
internal sealed class DefaultAuthorizationEngine : IAuthorizationEngine
{
    private readonly IRoleStore _roleStore;
    private readonly IAssignmentStore _assignmentStore;

    /// <summary>
    /// Initializes a new instance of the DefaultAuthorizationEngine class.
    /// </summary>
    /// <param name="roleStore">The store for retrieving role definitions.</param>
    /// <param name="assignmentStore">The store for retrieving role assignments.</param>
    public DefaultAuthorizationEngine(IRoleStore roleStore, IAssignmentStore assignmentStore)
    {
        _roleStore = roleStore;
        _assignmentStore = assignmentStore;
    }

    /// <summary>
    /// Begins an authorization check for the specified principal.
    /// </summary>
    /// <param name="principal">The principal whose permissions should be checked.</param>
    /// <returns>An authorization check builder for configuring and evaluating the authorization request.</returns>
    public IAuthorizationCheck For(PrincipalId principal)
    {
        return new AuthorizationCheckImplementation(principal, _roleStore, _assignmentStore);
    }
}