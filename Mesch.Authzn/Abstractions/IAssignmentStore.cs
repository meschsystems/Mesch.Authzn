namespace Mesch.Authzn;

/// <summary>
/// Defines a store for retrieving role assignments for principals.
/// Implementations can provide in-memory, database, or any other persistence mechanism.
/// </summary>
public interface IAssignmentStore
{
    /// <summary>
    /// Retrieves all role assignments for a specific principal.
    /// </summary>
    /// <param name="principal">The principal whose assignments should be retrieved.</param>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>A read-only list of assignments for the principal.</returns>
    Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
        PrincipalId principal, CancellationToken ct = default);
}