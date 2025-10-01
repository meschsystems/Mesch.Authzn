namespace Mesch.Authzn;

/// <summary>
/// Represents a unique identifier for a permission.
/// </summary>
/// <param name="Value">The string value of the permission identifier.</param>
public readonly record struct PermissionId(string Value)
{
    /// <summary>
    /// Implicitly converts a string to a PermissionId.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    public static implicit operator PermissionId(string value) => new(value);

    /// <summary>
    /// Returns the string representation of the permission identifier.
    /// </summary>
    /// <returns>The permission identifier value.</returns>
    public override string ToString() => Value;
}