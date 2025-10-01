namespace Mesch.Authzn;

/// <summary>
/// Represents the result of an authorization evaluation, indicating whether access is allowed and providing diagnostic information.
/// </summary>
public sealed class AuthorizationDecision
{
    /// <summary>
    /// Gets a value indicating whether the authorization request was allowed.
    /// </summary>
    public bool IsAllowed { get; }

    /// <summary>
    /// Gets the reason why authorization was denied, or None if allowed.
    /// </summary>
    public DenyReason DenyReason { get; }

    /// <summary>
    /// Gets the role that provided the matching permission, if authorization was allowed.
    /// </summary>
    public RoleId? MatchedRole { get; }

    /// <summary>
    /// Gets the permission that was matched, if authorization was allowed.
    /// </summary>
    public PermissionId? MatchedPermission { get; }

    /// <summary>
    /// Initializes a new instance of the AuthorizationDecision class.
    /// </summary>
    /// <param name="allowed">Whether the authorization request was allowed.</param>
    /// <param name="denyReason">The reason for denial, or None if allowed.</param>
    /// <param name="matchedRole">The role that provided the permission, if allowed.</param>
    /// <param name="matchedPermission">The permission that was matched, if allowed.</param>
    public AuthorizationDecision(
        bool allowed,
        DenyReason denyReason,
        RoleId? matchedRole = null,
        PermissionId? matchedPermission = null)
    {
        IsAllowed = allowed;
        DenyReason = denyReason;
        MatchedRole = matchedRole;
        MatchedPermission = matchedPermission;
    }

    /// <summary>
    /// Creates an authorization decision indicating that access is allowed.
    /// </summary>
    /// <param name="role">The role that provided the matching permission.</param>
    /// <param name="permission">The permission that was matched.</param>
    /// <returns>An AuthorizationDecision indicating allowed access.</returns>
    public static AuthorizationDecision Allow(RoleId role, PermissionId permission) =>
        new(true, DenyReason.None, role, permission);

    /// <summary>
    /// Creates an authorization decision indicating that access is denied.
    /// </summary>
    /// <param name="reason">The reason why access was denied.</param>
    /// <returns>An AuthorizationDecision indicating denied access.</returns>
    public static AuthorizationDecision Deny(DenyReason reason) =>
        new(false, reason);
}