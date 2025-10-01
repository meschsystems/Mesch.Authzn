namespace Mesch.Authzn;

/// <summary>
/// Specifies the reason why an authorization request was denied.
/// </summary>
public enum DenyReason
{
    /// <summary>
    /// The authorization was allowed. No denial occurred.
    /// </summary>
    None = 0,

    /// <summary>
    /// The principal has no active role assignments.
    /// </summary>
    NoAssignments,

    /// <summary>
    /// The principal has active roles, but none grant the requested permission.
    /// </summary>
    NoMatchingPermission,

    /// <summary>
    /// The permission exists in a role, but the requested scope does not match the granted scope.
    /// </summary>
    ScopeMismatch,

    /// <summary>
    /// The principal has a role assignment, but it is not currently active due to time constraints or revocation.
    /// </summary>
    AssignmentNotActive,

    /// <summary>
    /// An attribute-based access control (ABAC) condition evaluated to false or threw an exception.
    /// </summary>
    AttributeEvaluationFailed
}