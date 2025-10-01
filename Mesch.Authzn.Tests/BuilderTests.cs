namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for builder and host functionality.
/// </summary>
public class BuilderTests
{
    [Fact]
    public void Builder_CanCreate_EmptyHost()
    {
        var host = AuthorizationBuilder.Create().Build();

        Assert.NotNull(host);
        Assert.NotNull(host.Engine);
    }

    [Fact]
    public void Builder_CanAddRole_Fluently()
    {
        var host = AuthorizationBuilder.Create()
            .AddRole("role:admin", r =>
            {
                r.Grant("system.read");
                r.Grant("system.write");
            })
            .Build();

        Assert.NotNull(host);
    }

    [Fact]
    public void Builder_CanChainMultiple_Operations()
    {
        var host = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system.*"))
            .AddRole("role:reader", r => r.Grant("system.read"))
            .Assign("user:1", "role:admin")
            .Assign("user:2", "role:reader")
            .Build();

        Assert.NotNull(host);
    }

    [Fact]
    public async Task Host_AddRole_WorksAtRuntime()
    {
        var host = AuthorizationBuilder.Create()
            .Assign("user:1", "role:dynamic")
            .Build();

        var role = new Role("role:dynamic", "Dynamic", new List<PermissionGrant>
        {
            new PermissionGrant("test.permission")
        });
        host.AddRole(role);

        var decision = await host.Engine.For("user:1").On("test.permission").EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task Host_AddAssignment_WorksAtRuntime()
    {
        var host = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system.read"))
            .Build();

        host.AddAssignment(new Assignment("user:new", "role:admin"));

        var decision = await host.Engine.For("user:new").On("system.read").EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task Host_Revoke_WorksAtRuntime()
    {
        var host = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system.read"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision1 = await host.Engine.For("user:1").On("system.read").EvaluateAsync();
        Assert.True(decision1.IsAllowed);

        host.Revoke("user:1", "role:admin");

        var decision2 = await host.Engine.For("user:1").On("system.read").EvaluateAsync();
        Assert.False(decision2.IsAllowed);
    }
}