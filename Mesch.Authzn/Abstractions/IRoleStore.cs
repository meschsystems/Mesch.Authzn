namespace Mesch.Authzn;

/// <summary>
/// Defines a store for retrieving role definitions.
/// Implementations can provide in-memory, database, or any other persistence mechanism.
/// </summary>
public interface IRoleStore
{
    /// <summary>
    /// Retrieves a role by its identifier.
    /// </summary>
    /// <param name="id">The unique identifier of the role to retrieve.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>The role if found; otherwise, null.</returns>
    Task<Role?> GetRoleAsync(RoleId id, CancellationToken ct = default);
}