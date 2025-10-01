namespace Mesch.Authzn;

/// <summary>
/// Provides an in-memory implementation of IRoleStore for storing and retrieving role definitions.
/// This implementation is suitable for development, testing, and applications where roles are defined at startup.
/// </summary>
public sealed class InMemoryRoleStore : IRoleStore
{
    private readonly Dictionary<RoleId, Role> _roles = [];

    /// <summary>
    /// Adds or updates a role in the store.
    /// </summary>
    /// <param name="role">The role to add or update.</param>
    public void Add(Role role)
    {
        _roles[role.Id] = role;
    }

    /// <summary>
    /// Retrieves a role by its identifier.
    /// </summary>
    /// <param name="id">The unique identifier of the role to retrieve.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>The role if found; otherwise, null.</returns>
    public Task<Role?> GetRoleAsync(RoleId id, CancellationToken ct = default)
    {
        _roles.TryGetValue(id, out var role);
        return Task.FromResult(role);
    }
}