namespace Mesch.Authzn;

/// <summary>
/// Defines the entry point for authorization evaluation, providing a fluent interface for checking permissions.
/// </summary>
public interface IAuthorizationEngine
{
    /// <summary>
    /// Begins an authorization check for the specified principal.
    /// </summary>
    /// <param name="principal">The principal whose permissions should be checked.</param>
    /// <returns>An authorization check builder for configuring and evaluating the authorization request.</returns>
    IAuthorizationCheck For(PrincipalId principal);
}