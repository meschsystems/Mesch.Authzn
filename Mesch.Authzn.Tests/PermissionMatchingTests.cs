namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for wildcard permission matching.
/// </summary>
public class PermissionMatchingTests
{
    [Fact]
    public async Task PermissionMatching_ExactMatch_Works()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.read"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("invoice.read")
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task PermissionMatching_Wildcard_MatchesAll()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.*"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision1 = await auth.Engine.For("user:1").On("invoice.read").EvaluateAsync();
        var decision2 = await auth.Engine.For("user:1").On("invoice.write").EvaluateAsync();
        var decision3 = await auth.Engine.For("user:1").On("invoice.delete").EvaluateAsync();

        Assert.True(decision1.IsAllowed);
        Assert.True(decision2.IsAllowed);
        Assert.True(decision3.IsAllowed);
    }

    [Fact]
    public async Task PermissionMatching_Wildcard_DoesNotMatchDifferentPrefix()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.*"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("project.read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task PermissionMatching_Wildcard_MatchesNestedPermissions()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.*"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("invoice.approval.submit")
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }
}