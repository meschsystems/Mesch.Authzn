namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for attribute-based access control (ABAC).
/// </summary>
public class AbacTests
{
    [Fact]
    public async Task Abac_AllowsAccess_WhenConditionReturnsTrue()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:approver", r =>
                r.Grant(
                    "invoice:approve",
                    condition: attrs => (string)attrs["department"] == "finance"))
            .Assign("user:77", "role:approver")
            .Build();

        var decision = await auth.Engine
            .For("user:77")
            .On("invoice:approve")
            .WithAttributes(new AttributeBag { ["department"] = "finance" })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task Abac_DeniesAccess_WhenConditionReturnsFalse()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:approver", r =>
                r.Grant(
                    "invoice:approve",
                    condition: attrs => (string)attrs["department"] == "finance"))
            .Assign("user:77", "role:approver")
            .Build();

        var decision = await auth.Engine
            .For("user:77")
            .On("invoice:approve")
            .WithAttributes(new AttributeBag { ["department"] = "sales" })
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.AttributeEvaluationFailed, decision.DenyReason);
    }

    [Fact]
    public async Task Abac_DeniesAccess_WhenConditionThrowsException()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:approver", r =>
                r.Grant(
                    "invoice:approve",
                    condition: attrs => ((string)attrs["nonexistent"]).Length > 0))
            .Assign("user:77", "role:approver")
            .Build();

        var decision = await auth.Engine
            .For("user:77")
            .On("invoice:approve")
            .WithAttributes(new AttributeBag())
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.AttributeEvaluationFailed, decision.DenyReason);
    }

    [Fact]
    public async Task Abac_ComplexCondition_WithMultipleAttributes()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:manager", r =>
                r.Grant(
                    "budget:approve",
                    condition: attrs =>
                    {
                        var amount = Convert.ToDecimal(attrs["amount"]);
                        var level = Convert.ToInt32(attrs["level"]);
                        return level >= 3 && amount <= 100000;
                    }))
            .Assign("user:300", "role:manager")
            .Build();

        var decision1 = await auth.Engine
            .For("user:300")
            .On("budget:approve")
            .WithAttributes(new AttributeBag
            {
                ["amount"] = 50000m,
                ["level"] = 3
            })
            .EvaluateAsync();

        var decision2 = await auth.Engine
            .For("user:300")
            .On("budget:approve")
            .WithAttributes(new AttributeBag
            {
                ["amount"] = 150000m,
                ["level"] = 3
            })
            .EvaluateAsync();

        Assert.True(decision1.IsAllowed);
        Assert.False(decision2.IsAllowed);
    }

    [Fact]
    public async Task Abac_WorksWith_ScopeAndCondition()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:approver", r =>
                r.Grant(
                    "invoice:approve",
                    new ScopeBag { ["tenant"] = "acme" },
                    attrs => (string)attrs["department"] == "finance"))
            .Assign("user:77", "role:approver")
            .Build();

        var decision = await auth.Engine
            .For("user:77")
            .On("invoice:approve")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .WithAttributes(new AttributeBag { ["department"] = "finance" })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }
}