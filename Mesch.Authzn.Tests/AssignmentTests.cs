namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for Assignment domain logic.
/// </summary>
public class AssignmentTests
{
    [Fact]
    public void Assignment_IsActive_WhenNoConstraints()
    {
        var assignment = new Assignment("user:1", "role:admin");
        var now = DateTimeOffset.UtcNow;

        Assert.True(assignment.IsActiveAt(now));
        Assert.False(assignment.Revoked);
    }

    [Fact]
    public void Assignment_IsNotActive_WhenRevoked()
    {
        var assignment = new Assignment("user:1", "role:admin");
        assignment.Revoke();
        var now = DateTimeOffset.UtcNow;

        Assert.False(assignment.IsActiveAt(now));
        Assert.True(assignment.Revoked);
    }

    [Fact]
    public void Assignment_IsNotActive_BeforeNotBefore()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(1);
        var assignment = new Assignment("user:1", "role:admin", notBefore: notBefore);
        var now = DateTimeOffset.UtcNow;

        Assert.False(assignment.IsActiveAt(now));
    }

    [Fact]
    public void Assignment_IsActive_AfterNotBefore()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var assignment = new Assignment("user:1", "role:admin", notBefore: notBefore);
        var now = DateTimeOffset.UtcNow;

        Assert.True(assignment.IsActiveAt(now));
    }

    [Fact]
    public void Assignment_IsNotActive_AfterNotAfter()
    {
        var notAfter = DateTimeOffset.UtcNow.AddDays(-1);
        var assignment = new Assignment("user:1", "role:admin", notAfter: notAfter);
        var now = DateTimeOffset.UtcNow;

        Assert.False(assignment.IsActiveAt(now));
    }

    [Fact]
    public void Assignment_IsActive_BeforeNotAfter()
    {
        var notAfter = DateTimeOffset.UtcNow.AddDays(1);
        var assignment = new Assignment("user:1", "role:admin", notAfter: notAfter);
        var now = DateTimeOffset.UtcNow;

        Assert.True(assignment.IsActiveAt(now));
    }

    [Fact]
    public void Assignment_IsActive_WithinValidPeriod()
    {
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddDays(1);
        var assignment = new Assignment("user:1", "role:admin", notBefore, notAfter);
        var now = DateTimeOffset.UtcNow;

        Assert.True(assignment.IsActiveAt(now));
    }
}