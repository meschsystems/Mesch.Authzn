namespace Mesch.Authzn;

/// <summary>
/// Provides a fluent interface for configuring and evaluating an authorization check.
/// </summary>
public interface IAuthorizationCheck
{
    /// <summary>
    /// Specifies the permission to check.
    /// </summary>
    /// <param name="permission">The permission identifier to evaluate.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    IAuthorizationCheck On(PermissionId permission);

    /// <summary>
    /// Specifies the scope in which the permission should be evaluated.
    /// The requested scope must match or be more specific than the granted scope.
    /// </summary>
    /// <param name="scope">The scope constraints for the permission check.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    IAuthorizationCheck InScope(ScopeBag scope);

    /// <summary>
    /// Specifies runtime attributes for attribute-based access control (ABAC) evaluation.
    /// These attributes are passed to any permission grant conditions.
    /// </summary>
    /// <param name="attributes">The attributes to use for condition evaluation.</param>
    /// <returns>The authorization check builder for method chaining.</returns>
    IAuthorizationCheck WithAttributes(AttributeBag attributes);

    /// <summary>
    /// Evaluates the authorization check and returns a decision.
    /// </summary>
    /// <param name="ct">A cancellation token to cancel the operation.</param>
    /// <returns>An authorization decision indicating whether access is allowed and providing diagnostic information.</returns>
    /// <exception cref="InvalidOperationException">Thrown if On() was not called to specify a permission.</exception>
    Task<AuthorizationDecision> EvaluateAsync(CancellationToken ct = default);
}