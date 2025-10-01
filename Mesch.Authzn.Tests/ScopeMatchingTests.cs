namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for scope-based authorization.
/// </summary>
public class ScopeMatchingTests
{
    [Fact]
    public async Task ScopeMatching_AllowsAccess_WhenScopeMatches()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:tenant-admin", r =>
                r.Grant("invoice.read", new ScopeBag { ["tenant"] = "acme" }))
            .Assign("user:99", "role:tenant-admin")
            .Build();

        var decision = await auth.Engine
            .For("user:99")
            .On("invoice.read")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task ScopeMatching_DeniesAccess_WhenScopeMismatches()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:tenant-admin", r =>
                r.Grant("invoice.read", new ScopeBag { ["tenant"] = "acme" }))
            .Assign("user:99", "role:tenant-admin")
            .Build();

        var decision = await auth.Engine
            .For("user:99")
            .On("invoice.read")
            .InScope(new ScopeBag { ["tenant"] = "other" })
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.ScopeMismatch, decision.DenyReason);
    }

    [Fact]
    public async Task ScopeMatching_AllowsAccess_WhenRequestedScopeIsMoreSpecific()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:tenant-admin", r =>
                r.Grant("invoice.read", new ScopeBag { ["tenant"] = "acme" }))
            .Assign("user:99", "role:tenant-admin")
            .Build();

        var decision = await auth.Engine
            .For("user:99")
            .On("invoice.read")
            .InScope(new ScopeBag
            {
                ["tenant"] = "acme",
                ["project"] = "alpha"
            })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }

    [Fact]
    public async Task ScopeMatching_DeniesAccess_WhenRequestedScopeMissesRequiredKey()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r =>
                r.Grant("invoice.read", new ScopeBag
                {
                    ["tenant"] = "acme",
                    ["project"] = "alpha"
                }))
            .Assign("user:99", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:99")
            .On("invoice.read")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.ScopeMismatch, decision.DenyReason);
    }

    [Fact]
    public async Task ScopeMatching_AllowsAccess_WhenNoScopeConstraints()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:admin", r => r.Grant("invoice.read"))
            .Assign("user:1", "role:admin")
            .Build();

        var decision = await auth.Engine
            .For("user:1")
            .On("invoice.read")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
    }
}