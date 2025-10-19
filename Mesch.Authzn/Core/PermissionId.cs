namespace Mesch.Authzn;

/// <summary>
/// Represents a unique identifier for a permission composed of a resource and an action.
/// Format: "resource:action" (e.g., "documents:read", "roles:write", "*" for all)
/// </summary>
public readonly record struct PermissionId
{
    /// <summary>
    /// Gets the resource component of the permission (e.g., "documents", "roles", "*").
    /// </summary>
    public string Resource { get; }

    /// <summary>
    /// Gets the action component of the permission (e.g., "read", "write", "delete", "*").
    /// </summary>
    public string Action { get; }

    /// <summary>
    /// Initializes a new instance of PermissionId from resource and action components.
    /// </summary>
    /// <param name="resource">The resource component (e.g., "documents", "*").</param>
    /// <param name="action">The action component (e.g., "read", "write", "*").</param>
    public PermissionId(string resource, string action)
    {
        Resource = resource ?? throw new ArgumentNullException(nameof(resource));
        Action = action ?? throw new ArgumentNullException(nameof(action));
    }

    /// <summary>
    /// Parses a permission string in "resource:action" format into a PermissionId.
    /// Supports hierarchical resources: the last colon-separated segment is the action,
    /// everything before it is the resource.
    /// Examples:
    /// - "documents:read" → resource="documents", action="read"
    /// - "project:task:read" → resource="project:task", action="read"
    /// - "project:task:*" → resource="project:task", action="*"
    /// - "*" → resource="*", action="*"
    /// </summary>
    /// <param name="permissionString">The permission string to parse.</param>
    /// <returns>A PermissionId representing the parsed permission.</returns>
    /// <exception cref="ArgumentException">Thrown if the format is invalid.</exception>
    public static PermissionId Parse(string permissionString)
    {
        if (string.IsNullOrWhiteSpace(permissionString))
        {
            throw new ArgumentException("Permission string cannot be null or empty", nameof(permissionString));
        }

        // Handle wildcard case
        if (permissionString == "*")
        {
            return new PermissionId("*", "*");
        }

        // Split on last colon: everything before = resource, last part = action
        var lastColonIndex = permissionString.LastIndexOf(':');
        if (lastColonIndex == -1)
        {
            throw new ArgumentException(
                $"Permission string must contain at least one ':', got: {permissionString}",
                nameof(permissionString));
        }

        var resource = permissionString[..lastColonIndex];
        var action = permissionString[(lastColonIndex + 1)..];

        if (string.IsNullOrWhiteSpace(resource) || string.IsNullOrWhiteSpace(action))
        {
            throw new ArgumentException(
                $"Permission string must have non-empty resource and action parts, got: {permissionString}",
                nameof(permissionString));
        }

        return new PermissionId(resource, action);
    }

    /// <summary>
    /// Tries to parse a permission string into a PermissionId.
    /// </summary>
    /// <param name="permissionString">The permission string to parse.</param>
    /// <param name="permission">The parsed PermissionId if successful.</param>
    /// <returns>True if parsing succeeded; otherwise, false.</returns>
    public static bool TryParse(string permissionString, out PermissionId permission)
    {
        try
        {
            permission = Parse(permissionString);
            return true;
        }
        catch
        {
            permission = default;
            return false;
        }
    }

    /// <summary>
    /// Implicitly converts a string to a PermissionId by parsing it.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    public static implicit operator PermissionId(string value) => Parse(value);

    /// <summary>
    /// Returns the string representation of the permission in "resource:action" format.
    /// </summary>
    /// <returns>The permission identifier value (e.g., "documents:read", "*").</returns>
    public override string ToString()
    {
        // Special case for all permissions
        if (Resource == "*" && Action == "*")
        {
            return "*";
        }

        return $"{Resource}:{Action}";
    }

    /// <summary>
    /// Gets the string representation (same as ToString()).
    /// </summary>
    public string Value => ToString();
}