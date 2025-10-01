namespace Mesch.Authzn;

/// <summary>
/// Provides a fluent interface for building role definitions with permission grants.
/// </summary>
public sealed class RoleBuilder
{
    private readonly RoleId _roleId;
    private readonly string _name;
    private readonly List<PermissionGrant> _grants = [];

    /// <summary>
    /// Initializes a new instance of the RoleBuilder class.
    /// </summary>
    /// <param name="roleId">The unique identifier for the role being built.</param>
    /// <param name="name">The human-readable name for the role.</param>
    internal RoleBuilder(RoleId roleId, string name)
    {
        _roleId = roleId;
        _name = name;
    }

    /// <summary>
    /// Adds a permission grant to the role being built.
    /// </summary>
    /// <param name="permission">The permission to grant. Supports wildcard notation with '.*' suffix.</param>
    /// <param name="scope">Optional scope constraints that limit where the permission applies.</param>
    /// <param name="condition">Optional ABAC condition that must evaluate to true for the grant to apply.</param>
    /// <returns>The role builder for method chaining.</returns>
    public RoleBuilder Grant(
        string permission,
        ScopeBag? scope = null,
        Func<AttributeBag, bool>? condition = null)
    {
        _grants.Add(new PermissionGrant(permission, scope, condition));
        return this;
    }

    /// <summary>
    /// Builds the role from the configured grants.
    /// </summary>
    /// <returns>A role instance with the configured grants.</returns>
    internal Role Build()
    {
        return new Role(_roleId, _name, _grants);
    }
}