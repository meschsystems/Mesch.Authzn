namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for multiple roles and complex scenarios.
/// </summary>
public class MultiRoleTests
{
    [Fact]
    public async Task MultiRole_AllowsAccess_FromAnyAssignedRole()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice.read"))
            .AddRole("role:writer", r => r.Grant("invoice.write"))
            .Assign("user:100", "role:reader")
            .Assign("user:100", "role:writer")
            .Build();

        var decision1 = await auth.Engine.For("user:100").On("invoice.read").EvaluateAsync();
        var decision2 = await auth.Engine.For("user:100").On("invoice.write").EvaluateAsync();

        Assert.True(decision1.IsAllowed);
        Assert.True(decision2.IsAllowed);
    }

    [Fact]
    public async Task MultiRole_ReturnsFirstMatchingRole()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.*"))
            .AddRole("role:reader", r => r.Grant("invoice.read"))
            .Assign("user:100", "role:admin")
            .Assign("user:100", "role:reader")
            .Build();

        var decision = await auth.Engine.For("user:100").On("invoice.read").EvaluateAsync();

        Assert.True(decision.IsAllowed);
        Assert.NotNull(decision.MatchedRole);
    }

    [Fact]
    public async Task MultiRole_DeniesAccess_WhenNoRoleGrantsPermission()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice.read"))
            .AddRole("role:viewer", r => r.Grant("invoice.view"))
            .Assign("user:100", "role:reader")
            .Assign("user:100", "role:viewer")
            .Build();

        var decision = await auth.Engine.For("user:100").On("invoice.delete").EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.NoMatchingPermission, decision.DenyReason);
    }
}