namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for AuthorizationDecision helper methods.
/// </summary>
public class AuthorizationDecisionTests
{
    [Fact]
    public void AuthorizationDecision_Allow_CreatesAllowedDecision()
    {
        var decision = AuthorizationDecision.Allow("role:admin", "system:read");

        Assert.True(decision.IsAllowed);
        Assert.Equal(DenyReason.None, decision.DenyReason);
        Assert.Equal("role:admin", decision.MatchedRole?.Value);
        Assert.Equal("system:read", decision.MatchedPermission?.Value);
    }

    [Fact]
    public void AuthorizationDecision_Deny_CreatesDeniedDecision()
    {
        var decision = AuthorizationDecision.Deny(DenyReason.NoAssignments);

        Assert.False(decision.IsAllowed);
        Assert.Equal(DenyReason.NoAssignments, decision.DenyReason);
        Assert.Null(decision.MatchedRole);
        Assert.Null(decision.MatchedPermission);
    }
}