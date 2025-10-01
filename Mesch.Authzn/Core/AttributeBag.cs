namespace Mesch.Authzn;

/// <summary>
/// A key-value collection that provides contextual attributes for attribute-based access control (ABAC) evaluation.
/// Attributes can include runtime values such as request amount, user department, or resource properties.
/// </summary>
public sealed class AttributeBag : Dictionary<string, object>
{
    /// <summary>
    /// Initializes a new instance of the AttributeBag class that is empty.
    /// </summary>
    public AttributeBag() { }

    /// <summary>
    /// Initializes a new instance of the AttributeBag class that contains elements copied from the specified dictionary.
    /// </summary>
    /// <param name="dictionary">The dictionary whose elements are copied to the new AttributeBag.</param>
    public AttributeBag(IDictionary<string, object> dictionary) : base(dictionary) { }
}