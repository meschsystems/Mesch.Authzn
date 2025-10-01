namespace Mesch.Authzn;

/// <summary>
/// Represents a reusable definition of authority that grants a collection of permissions.
/// Roles are stable and timeless definitions that are assigned to principals via assignments.
/// </summary>
public sealed class Role
{
    /// <summary>
    /// Gets the unique identifier for this role.
    /// </summary>
    public RoleId Id { get; }

    /// <summary>
    /// Gets the human-readable name of the role.
    /// </summary>
    public string Name { get; }

    /// <summary>
    /// Gets the collection of permission grants that this role provides.
    /// </summary>
    public IReadOnlyCollection<PermissionGrant> Grants { get; }

    /// <summary>
    /// Initializes a new instance of the Role class.
    /// </summary>
    /// <param name="id">The unique identifier for the role.</param>
    /// <param name="name">The human-readable name of the role.</param>
    /// <param name="grants">The collection of permission grants that this role provides.</param>
    public Role(RoleId id, string name, IReadOnlyCollection<PermissionGrant> grants)
    {
        Id = id;
        Name = name;
        Grants = grants;
    }
}