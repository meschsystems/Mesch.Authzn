namespace Mesch.Authzn;

/// <summary>
/// Provides an in-memory implementation of IAssignmentStore for storing and retrieving role assignments.
/// This implementation is suitable for development, testing, and applications where assignments are managed in memory.
/// </summary>
public sealed class InMemoryAssignmentStore : IAssignmentStore
{
    private readonly List<Assignment> _assignments = [];

    /// <summary>
    /// Adds a new assignment to the store.
    /// </summary>
    /// <param name="assignment">The assignment to add.</param>
    public void Add(Assignment assignment)
    {
        _assignments.Add(assignment);
    }

    /// <summary>
    /// Revokes an existing assignment by marking it as revoked.
    /// </summary>
    /// <param name="principal">The principal whose assignment should be revoked.</param>
    /// <param name="role">The role to revoke from the principal.</param>
    public void Revoke(PrincipalId principal, RoleId role)
    {
        var match = _assignments.FirstOrDefault(a =>
            a.Principal.Value == principal.Value && a.Role.Value == role.Value);
        match?.Revoke();
    }

    /// <summary>
    /// Retrieves all role assignments for a specific principal.
    /// </summary>
    /// <param name="principal">The principal whose assignments should be retrieved.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A read-only list of assignments for the principal.</returns>
    public Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
        PrincipalId principal, CancellationToken ct = default)
    {
        var results = _assignments
            .Where(a => a.Principal.Value == principal.Value)
            .ToList();
        return Task.FromResult<IReadOnlyList<Assignment>>(results);
    }
}