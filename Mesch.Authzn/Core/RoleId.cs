namespace Mesch.Authzn;

/// <summary>
/// Represents a unique identifier for a role.
/// </summary>
/// <param name="Value">The string value of the role identifier.</param>
public readonly record struct RoleId(string Value)
{
    /// <summary>
    /// Implicitly converts a string to a RoleId.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    public static implicit operator RoleId(string value) => new(value);

    /// <summary>
    /// Returns the string representation of the role identifier.
    /// </summary>
    /// <returns>The role identifier value.</returns>
    public override string ToString() => Value;
}