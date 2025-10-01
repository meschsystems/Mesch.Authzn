namespace Mesch.Authzn;

/// <summary>
/// Hosts the authorization engine and provides convenience methods for managing roles and assignments at runtime.
/// </summary>
public sealed class AuthorizationHost
{
    private readonly IRoleStore _roleStore;
    private readonly IAssignmentStore _assignmentStore;

    /// <summary>
    /// Gets the authorization engine for evaluating permission checks.
    /// </summary>
    public IAuthorizationEngine Engine { get; }

    /// <summary>
    /// Initializes a new instance of the AuthorizationHost class.
    /// </summary>
    /// <param name="roleStore">The role store to use for retrieving role definitions.</param>
    /// <param name="assignmentStore">The assignment store to use for retrieving role assignments.</param>
    internal AuthorizationHost(IRoleStore roleStore, IAssignmentStore assignmentStore)
    {
        _roleStore = roleStore;
        _assignmentStore = assignmentStore;
        Engine = new DefaultAuthorizationEngine(roleStore, assignmentStore);
    }

    /// <summary>
    /// Adds a role to the in-memory role store at runtime.
    /// Only supported when using InMemoryRoleStore.
    /// </summary>
    /// <param name="role">The role to add.</param>
    /// <exception cref="InvalidOperationException">Thrown if not using InMemoryRoleStore.</exception>
    public void AddRole(Role role)
    {
        if (_roleStore is InMemoryRoleStore inMemoryStore)
        {
            inMemoryStore.Add(role);
        }
        else
        {
            throw new InvalidOperationException(
                "AddRole is only supported with InMemoryRoleStore");
        }
    }

    /// <summary>
    /// Adds an assignment to the in-memory assignment store at runtime.
    /// Only supported when using InMemoryAssignmentStore.
    /// </summary>
    /// <param name="assignment">The assignment to add.</param>
    /// <exception cref="InvalidOperationException">Thrown if not using InMemoryAssignmentStore.</exception>
    public void AddAssignment(Assignment assignment)
    {
        if (_assignmentStore is InMemoryAssignmentStore inMemoryStore)
        {
            inMemoryStore.Add(assignment);
        }
        else
        {
            throw new InvalidOperationException(
                "AddAssignment is only supported with InMemoryAssignmentStore");
        }
    }

    /// <summary>
    /// Revokes an assignment from the in-memory assignment store at runtime.
    /// Only supported when using InMemoryAssignmentStore.
    /// </summary>
    /// <param name="principalId">The principal whose assignment should be revoked.</param>
    /// <param name="roleId">The role to revoke from the principal.</param>
    /// <exception cref="InvalidOperationException">Thrown if not using InMemoryAssignmentStore.</exception>
    public void Revoke(PrincipalId principalId, RoleId roleId)
    {
        if (_assignmentStore is InMemoryAssignmentStore inMemoryStore)
        {
            inMemoryStore.Revoke(principalId, roleId);
        }
        else
        {
            throw new InvalidOperationException(
                "Revoke is only supported with InMemoryAssignmentStore");
        }
    }
}