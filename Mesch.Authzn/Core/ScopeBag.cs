namespace Mesch.Authzn;

/// <summary>
/// A key-value collection that defines the scope in which permissions apply.
/// Scope constraints allow permissions to be limited to specific contexts such as tenants, projects, or resources.
/// </summary>
public sealed class ScopeBag : Dictionary<string, string>
{
    /// <summary>
    /// Initializes a new instance of the ScopeBag class that is empty.
    /// </summary>
    public ScopeBag() { }

    /// <summary>
    /// Initializes a new instance of the ScopeBag class that contains elements copied from the specified dictionary.
    /// </summary>
    /// <param name="dictionary">The dictionary whose elements are copied to the new ScopeBag.</param>
    public ScopeBag(IDictionary<string, string> dictionary) : base(dictionary) { }
}