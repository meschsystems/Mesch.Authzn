namespace Mesch.Authzn;

/// <summary>
/// Represents a unique identifier for a principal (user, service, or group).
/// </summary>
/// <param name="Value">The string value of the principal identifier.</param>
public readonly record struct PrincipalId(string Value)
{
    /// <summary>
    /// Implicitly converts a string to a PrincipalId.
    /// </summary>
    /// <param name="value">The string value to convert.</param>
    public static implicit operator PrincipalId(string value) => new(value);

    /// <summary>
    /// Returns the string representation of the principal identifier.
    /// </summary>
    /// <returns>The principal identifier value.</returns>
    public override string ToString() => Value;
}