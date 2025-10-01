namespace Mesch.Authzn;

/// <summary>
/// Provides a fluent interface for configuring and building an authorization host with roles and assignments.
/// </summary>
public sealed class AuthorizationBuilder
{
    private IRoleStore _roleStore = new InMemoryRoleStore();
    private IAssignmentStore _assignmentStore = new InMemoryAssignmentStore();
    private readonly List<Role> _pendingRoles = [];
    private readonly List<Assignment> _pendingAssignments = [];
    private readonly List<(PrincipalId, RoleId)> _pendingRevocations = [];

    private AuthorizationBuilder() { }

    /// <summary>
    /// Creates a new authorization builder instance.
    /// </summary>
    /// <returns>A new authorization builder.</returns>
    public static AuthorizationBuilder Create() => new();

    /// <summary>
    /// Adds a role definition to the authorization system.
    /// </summary>
    /// <param name="roleId">The unique identifier for the role.</param>
    /// <param name="configure">An action that configures the role's permission grants.</param>
    /// <returns>The authorization builder for method chaining.</returns>
    public AuthorizationBuilder AddRole(string roleId, Action<RoleBuilder> configure)
    {
        var builder = new RoleBuilder(roleId, roleId);
        configure(builder);
        _pendingRoles.Add(builder.Build());
        return this;
    }

    /// <summary>
    /// Assigns a role to a principal with optional time-based validity constraints.
    /// </summary>
    /// <param name="principalId">The principal to whom the role should be assigned.</param>
    /// <param name="roleId">The role to assign.</param>
    /// <param name="notBefore">Optional start time for the assignment. If null, active immediately.</param>
    /// <param name="notAfter">Optional expiration time for the assignment. If null, does not expire.</param>
    /// <returns>The authorization builder for method chaining.</returns>
    public AuthorizationBuilder Assign(
        string principalId,
        string roleId,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        _pendingAssignments.Add(new Assignment(principalId, roleId, notBefore, notAfter));
        return this;
    }

    /// <summary>
    /// Marks an assignment for revocation. The assignment will be revoked when Build() is called.
    /// </summary>
    /// <param name="principalId">The principal whose assignment should be revoked.</param>
    /// <param name="roleId">The role to revoke from the principal.</param>
    /// <returns>The authorization builder for method chaining.</returns>
    public AuthorizationBuilder Revoke(string principalId, string roleId)
    {
        _pendingRevocations.Add((principalId, roleId));
        return this;
    }

    /// <summary>
    /// Specifies a custom role store implementation to use instead of the default in-memory store.
    /// </summary>
    /// <param name="store">The role store implementation to use.</param>
    /// <returns>The authorization builder for method chaining.</returns>
    public AuthorizationBuilder UseRoleStore(IRoleStore store)
    {
        _roleStore = store;
        return this;
    }

    /// <summary>
    /// Specifies a custom assignment store implementation to use instead of the default in-memory store.
    /// </summary>
    /// <param name="store">The assignment store implementation to use.</param>
    /// <returns>The authorization builder for method chaining.</returns>
    public AuthorizationBuilder UseAssignmentStore(IAssignmentStore store)
    {
        _assignmentStore = store;
        return this;
    }

    /// <summary>
    /// Builds and returns an authorization host with all configured roles and assignments.
    /// If using in-memory stores, this method populates them with the configured data.
    /// </summary>
    /// <returns>An authorization host ready for use.</returns>
    public AuthorizationHost Build()
    {
        if (_roleStore is InMemoryRoleStore inMemoryRoles)
        {
            foreach (var role in _pendingRoles)
            {
                inMemoryRoles.Add(role);
            }
        }

        if (_assignmentStore is InMemoryAssignmentStore inMemoryAssignments)
        {
            foreach (var assignment in _pendingAssignments)
            {
                inMemoryAssignments.Add(assignment);
            }

            foreach (var (principalId, roleId) in _pendingRevocations)
            {
                inMemoryAssignments.Revoke(principalId, roleId);
            }
        }

        return new AuthorizationHost(_roleStore, _assignmentStore);
    }
}