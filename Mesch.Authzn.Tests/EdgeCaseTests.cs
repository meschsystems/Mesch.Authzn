namespace Mesch.Authzn.Tests;
/// <summary>
/// Edge case and error handling tests.
/// </summary>
public class EdgeCaseTests
{
    [Fact]
    public async Task EdgeCase_EmptyRoleGrants_DeniesAllAccess()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:empty", r => { })
            .Assign("user:1", "role:empty")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("any:permission")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task EdgeCase_NonExistentRole_DeniesAccess()
    {
        var roleStore = new InMemoryRoleStore();
        var assignmentStore = new InMemoryAssignmentStore();
        assignmentStore.Add(new Assignment("user:1", "role:nonexistent"));

        var host = AuthorizationBuilder.Create()
            .UseRoleStore(roleStore)
            .UseAssignmentStore(assignmentStore)
            .Build();

        var decision = await host.Engine
            .For("user:1")
            .On("any:permission")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
    }

    [Fact]
    public async Task EdgeCase_EmptyScope_MatchesAnyRequest()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system:read", new ScopeBag()))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("system:read")
            .InScope(new ScopeBag { ["tenant"] = "any" })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task EdgeCase_NoScopeInRequest_WorksWithEmptyGrantScope()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system:read"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("system:read")
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task EdgeCase_MultipleAssignments_SameRole_FirstWins()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("system:read"))
            .Assign("user:1", "role:admin")
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("system:read")
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task EdgeCase_WildcardPermission_DoesNotMatchWithoutDot()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice:*"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("invoices:read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
    }
}