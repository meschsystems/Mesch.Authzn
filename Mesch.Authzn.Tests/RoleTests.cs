namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for Role and PermissionGrant.
/// </summary>
public class RoleTests
{
    [Fact]
    public void Role_CanBeCreated_WithGrants()
    {
        var grants = new List<PermissionGrant>
        {
            new PermissionGrant("invoice:read"),
            new PermissionGrant("invoice:write")
        };
        var role = new Role("role:admin", "Administrator", grants);

        Assert.Equal("role:admin", role.Id.Value);
        Assert.Equal("Administrator", role.Name);
        Assert.Equal(2, role.Grants.Count);
    }

    [Fact]
    public void PermissionGrant_UsesEmptyScope_WhenNoneProvided()
    {
        var grant = new PermissionGrant("invoice:read");

        Assert.NotNull(grant.Scope);
        Assert.Empty(grant.Scope);
        Assert.Null(grant.Condition);
    }

    [Fact]
    public void PermissionGrant_CanHaveScope()
    {
        var scope = new ScopeBag { ["tenant"] = "acme" };
        var grant = new PermissionGrant("invoice:read", scope);

        Assert.Single(grant.Scope);
        Assert.Equal("acme", grant.Scope["tenant"]);
    }

    [Fact]
    public void PermissionGrant_CanHaveCondition()
    {
        var grant = new PermissionGrant(
            "invoice:approve",
            condition: attrs => (string)attrs["department"] == "finance");

        Assert.NotNull(grant.Condition);

        var attrs = new AttributeBag { ["department"] = "finance" };
        Assert.True(grant.Condition(attrs));

        var attrs2 = new AttributeBag { ["department"] = "sales" };
        Assert.False(grant.Condition(attrs2));
    }
}