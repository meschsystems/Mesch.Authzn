namespace Mesch.Authzn;

/// <summary>
/// Internal implementation of the authorization check builder and evaluator.
/// </summary>
internal sealed class AuthorizationCheckImplementation : IAuthorizationCheck
{
    private readonly PrincipalId _principal;
    private readonly IRoleStore _roleStore;
    private readonly IAssignmentStore _assignmentStore;
    private PermissionId? _permission;
    private ScopeBag _scope = [];
    private AttributeBag _attributes = [];

    /// <summary>
    /// Initializes a new instance of the AuthorizationCheckImplementation class.
    /// </summary>
    /// <param name="principal">The principal being evaluated.</param>
    /// <param name="roleStore">The store for retrieving role definitions.</param>
    /// <param name="assignmentStore">The store for retrieving role assignments.</param>
    public AuthorizationCheckImplementation(
        PrincipalId principal,
        IRoleStore roleStore,
        IAssignmentStore assignmentStore)
    {
        _principal = principal;
        _roleStore = roleStore;
        _assignmentStore = assignmentStore;
    }

    /// <summary>
    /// Specifies the permission to check.
    /// </summary>
    /// <param name="permission">The permission identifier to evaluate.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    public IAuthorizationCheck On(PermissionId permission)
    {
        _permission = permission;
        return this;
    }

    /// <summary>
    /// Specifies the scope in which the permission should be evaluated.
    /// </summary>
    /// <param name="scope">The scope constraints for the permission check.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    public IAuthorizationCheck InScope(ScopeBag scope)
    {
        _scope = scope;
        return this;
    }

    /// <summary>
    /// Specifies runtime attributes for attribute-based access control (ABAC) evaluation.
    /// </summary>
    /// <param name="attributes">The attributes to use for condition evaluation.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    public IAuthorizationCheck WithAttributes(AttributeBag attributes)
    {
        _attributes = attributes;
        return this;
    }

    /// <summary>
    /// Evaluates the authorization check against the configured stores and returns a decision.
    /// </summary>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>An authorization decision indicating whether access is allowed.</returns>
    /// <exception cref="InvalidOperationException">Thrown if On() was not called to specify a permission.</exception>
    public async Task<AuthorizationDecision> EvaluateAsync(CancellationToken ct = default)
    {
        if (!_permission.HasValue)
        {
            throw new InvalidOperationException("Permission must be specified with On()");
        }

        var assignments = await _assignmentStore.GetAssignmentsForPrincipalAsync(_principal, ct);
        if (assignments.Count == 0)
        {
            return AuthorizationDecision.Deny(DenyReason.NoAssignments);
        }

        var now = DateTimeOffset.UtcNow;
        var activeAssignments = assignments.Where(a => a.IsActiveAt(now)).ToList();

        if (activeAssignments.Count == 0)
        {
            return AuthorizationDecision.Deny(DenyReason.AssignmentNotActive);
        }

        foreach (var assignment in activeAssignments)
        {
            var role = await _roleStore.GetRoleAsync(assignment.Role, ct);
            if (role is null)
            {
                continue;
            }

            foreach (var grant in role.Grants)
            {
                if (!PermissionMatches(grant.Permission, _permission.Value))
                {
                    continue;
                }

                if (!ScopeMatches(grant.Scope, _scope))
                {
                    continue;
                }

                if (grant.Condition is not null)
                {
                    try
                    {
                        if (!grant.Condition(_attributes))
                        {
                            return AuthorizationDecision.Deny(DenyReason.AttributeEvaluationFailed);
                        }
                    }
                    catch
                    {
                        return AuthorizationDecision.Deny(DenyReason.AttributeEvaluationFailed);
                    }
                }

                return AuthorizationDecision.Allow(role.Id, grant.Permission);
            }
        }

        var hasAnyPermission = false;
        foreach (var assignment in activeAssignments)
        {
            var role = await _roleStore.GetRoleAsync(assignment.Role, ct);
            if (role is not null && role.Grants.Count > 0)
            {
                hasAnyPermission = true;
                if (role.Grants.Any(g => PermissionMatches(g.Permission, _permission.Value)))
                {
                    return AuthorizationDecision.Deny(DenyReason.ScopeMismatch);
                }
            }
        }

        return AuthorizationDecision.Deny(
            hasAnyPermission ? DenyReason.NoMatchingPermission : DenyReason.NoMatchingPermission);
    }

    /// <summary>
    /// Determines whether a granted permission matches the requested permission.
    /// Supports exact matching and wildcard matching for both resource and action components.
    /// Wildcard "*" matches any value for that component.
    /// </summary>
    /// <param name="grant">The permission granted by a role.</param>
    /// <param name="requested">The permission being requested.</param>
    /// <returns>True if the granted permission matches the requested permission; otherwise, false.</returns>
    private static bool PermissionMatches(PermissionId grant, PermissionId requested)
    {
        // Check resource component
        var resourceMatches = grant.Resource == "*" ||
                             grant.Resource == requested.Resource;

        // Check action component
        var actionMatches = grant.Action == "*" ||
                           grant.Action == requested.Action;

        return resourceMatches && actionMatches;
    }

    /// <summary>
    /// Determines whether the requested scope matches or is more specific than the granted scope.
    /// All key-value pairs in the granted scope must be present in the requested scope with matching values.
    /// </summary>
    /// <param name="grantScope">The scope constraints defined in the permission grant.</param>
    /// <param name="requestedScope">The scope provided in the authorization check.</param>
    /// <returns>True if the requested scope satisfies the granted scope constraints; otherwise, false.</returns>
    private static bool ScopeMatches(ScopeBag grantScope, ScopeBag requestedScope)
    {
        foreach (var kvp in grantScope)
        {
            if (!requestedScope.TryGetValue(kvp.Key, out var requestedValue))
            {
                return false;
            }

            if (kvp.Value != requestedValue)
            {
                return false;
            }
        }

        return true;
    }
}