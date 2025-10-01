namespace Mesch.Authzn;

/// <summary>
/// Represents a grant of a specific permission, optionally constrained by scope and runtime attributes.
/// </summary>
public sealed class PermissionGrant
{
    /// <summary>
    /// Gets the permission being granted.
    /// </summary>
    public PermissionId Permission { get; }

    /// <summary>
    /// Gets the scope constraints that limit where this permission applies.
    /// An empty scope means the permission applies universally.
    /// </summary>
    public ScopeBag Scope { get; }

    /// <summary>
    /// Gets the optional attribute-based access control (ABAC) condition that must evaluate to true for the grant to apply.
    /// If null, no additional conditions are required beyond scope matching.
    /// </summary>
    public Func<AttributeBag, bool>? Condition { get; }

    /// <summary>
    /// Initializes a new instance of the PermissionGrant class.
    /// </summary>
    /// <param name="permission">The permission being granted.</param>
    /// <param name="scope">Optional scope constraints. If null, an empty scope is used.</param>
    /// <param name="condition">Optional ABAC condition delegate. If null, no attribute evaluation is performed.</param>
    public PermissionGrant(
        PermissionId permission,
        ScopeBag? scope = null,
        Func<AttributeBag, bool>? condition = null)
    {
        Permission = permission;
        Scope = scope ?? [];
        Condition = condition;
    }
}