namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for basic authorization scenarios.
/// </summary>
public class AuthorizationEngineBasicTests
{
    [Fact]
    public async Task AuthorizationEngine_AllowsAccess_WhenPermissionGranted()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader")
            .Build();

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:read")
            .EvaluateAsync();

        Assert.True(decision.IsAllowed);
        Assert.Equal(DenyReason.None, decision.DenyReason);
        Assert.Equal("role:reader", decision.MatchedRole?.Value);
    }

    [Fact]
    public async Task AuthorizationEngine_DeniesAccess_WhenNoAssignments()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Build();

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.NoAssignments, decision.DenyReason);
    }

    [Fact]
    public async Task AuthorizationEngine_DeniesAccess_WhenNoMatchingPermission()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader")
            .Build();

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:delete")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.NoMatchingPermission, decision.DenyReason);
    }

    [Fact]
    public async Task AuthorizationEngine_DeniesAccess_WhenAssignmentRevoked()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader")
            .Build();

        auth.Revoke("user:42", "role:reader");

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.AssignmentNotActive, decision.DenyReason);
    }

    [Fact]
    public async Task AuthorizationEngine_DeniesAccess_WhenAssignmentNotYetActive()
    {
        var tomorrow = DateTimeOffset.UtcNow.AddDays(1);
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader", notBefore: tomorrow)
            .Build();

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.AssignmentNotActive, decision.DenyReason);
    }

    [Fact]
    public async Task AuthorizationEngine_DeniesAccess_WhenAssignmentExpired()
    {
        var yesterday = DateTimeOffset.UtcNow.AddDays(-1);
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader", notAfter: yesterday)
            .Build();

        var decision = await auth.Engine
            .For("user:42")
            .On("invoice:read")
            .EvaluateAsync();

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.AssignmentNotActive, decision.DenyReason);
    }

    [Fact]
    public async Task AuthorizationEngine_ThrowsException_WhenPermissionNotSpecified()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:reader", r => r.Grant("invoice:read"))
            .Assign("user:42", "role:reader")
            .Build();

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await auth.Engine
                .For("user:42")
                .EvaluateAsync();
        });
    }
}