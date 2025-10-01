using Microsoft.Extensions.DependencyInjection;

namespace Mesch.Authzn;

/// <summary>
/// Provides extension methods for registering authorization services with the dependency injection container.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the authorization engine and host as singletons in the service collection.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    /// <param name="configure">Optional action to configure roles and assignments using the builder.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddAuthorizationEngine(
        this IServiceCollection services,
        Action<AuthorizationBuilder>? configure = null)
    {
        var builder = AuthorizationBuilder.Create();
        configure?.Invoke(builder);

        var host = builder.Build();

        services.AddSingleton(host);
        services.AddSingleton(host.Engine);

        return services;
    }

    /// <summary>
    /// Registers the authorization engine and host as singletons in the service collection using custom stores.
    /// </summary>
    /// <param name="services">The service collection to register services with.</param>
    /// <param name="roleStore">The role store implementation to use.</param>
    /// <param name="assignmentStore">The assignment store implementation to use.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddAuthorizationEngine(
        this IServiceCollection services,
        IRoleStore roleStore,
        IAssignmentStore assignmentStore)
    {
        var builder = AuthorizationBuilder.Create()
            .UseRoleStore(roleStore)
            .UseAssignmentStore(assignmentStore);

        var host = builder.Build();

        services.AddSingleton(host);
        services.AddSingleton(host.Engine);

        return services;
    }
}