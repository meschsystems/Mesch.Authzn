namespace Mesch.Authzn;

/// <summary>
/// Represents the assignment of a role to a principal, with optional time-based validity constraints.
/// Assignments are the only time-varying element in the authorization model.
/// </summary>
public sealed class Assignment
{
    /// <summary>
    /// Gets the principal to whom the role is assigned.
    /// </summary>
    public PrincipalId Principal { get; }

    /// <summary>
    /// Gets the role being assigned to the principal.
    /// </summary>
    public RoleId Role { get; }

    /// <summary>
    /// Gets the earliest time at which this assignment becomes active.
    /// If null, the assignment is active immediately.
    /// </summary>
    public DateTimeOffset? NotBefore { get; }

    /// <summary>
    /// Gets the time at which this assignment expires and is no longer active.
    /// If null, the assignment does not expire.
    /// </summary>
    public DateTimeOffset? NotAfter { get; }

    /// <summary>
    /// Gets a value indicating whether this assignment has been revoked.
    /// </summary>
    public bool Revoked { get; private set; }

    /// <summary>
    /// Initializes a new instance of the Assignment class.
    /// </summary>
    /// <param name="principal">The principal to whom the role is assigned.</param>
    /// <param name="role">The role being assigned.</param>
    /// <param name="notBefore">Optional start time for assignment validity.</param>
    /// <param name="notAfter">Optional expiration time for assignment validity.</param>
    public Assignment(
        PrincipalId principal,
        RoleId role,
        DateTimeOffset? notBefore = null,
        DateTimeOffset? notAfter = null)
    {
        Principal = principal;
        Role = role;
        NotBefore = notBefore;
        NotAfter = notAfter;
        Revoked = false;
    }

    /// <summary>
    /// Revokes this assignment, making it permanently inactive.
    /// </summary>
    public void Revoke() => Revoked = true;

    /// <summary>
    /// Determines whether this assignment is active at the specified time.
    /// </summary>
    /// <param name="now">The time to check against.</param>
    /// <returns>True if the assignment is active; otherwise, false.</returns>
    public bool IsActiveAt(DateTimeOffset now)
    {
        if (Revoked)
        {
            return false;
        }

        if (NotBefore.HasValue && now < NotBefore.Value)
        {
            return false;
        }

        if (NotAfter.HasValue && now >= NotAfter.Value)
        {
            return false;
        }

        return true;
    }
}