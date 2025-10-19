namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for core value objects and domain types.
/// </summary>
public class CoreTypesTests
{
    [Fact]
    public void PrincipalId_ImplicitConversion_FromString()
    {
        PrincipalId principalId = "user:123";

        Assert.Equal("user:123", principalId.Value);
        Assert.Equal("user:123", principalId.ToString());
    }

    [Fact]
    public void RoleId_ImplicitConversion_FromString()
    {
        RoleId roleId = "role:admin";

        Assert.Equal("role:admin", roleId.Value);
        Assert.Equal("role:admin", roleId.ToString());
    }

    [Fact]
    public void PermissionId_ImplicitConversion_FromString()
    {
        PermissionId permissionId = "invoice:read";

        Assert.Equal("invoice:read", permissionId.Value);
        Assert.Equal("invoice:read", permissionId.ToString());
    }

    [Fact]
    public void ScopeBag_CanInitialize_Empty()
    {
        var scope = new ScopeBag();

        Assert.Empty(scope);
    }

    [Fact]
    public void ScopeBag_CanInitialize_FromDictionary()
    {
        var dict = new Dictionary<string, string>
        {
            ["tenant"] = "acme",
            ["project"] = "alpha"
        };
        var scope = new ScopeBag(dict);

        Assert.Equal(2, scope.Count);
        Assert.Equal("acme", scope["tenant"]);
        Assert.Equal("alpha", scope["project"]);
    }

    [Fact]
    public void AttributeBag_CanInitialize_Empty()
    {
        var attributes = new AttributeBag();

        Assert.Empty(attributes);
    }

    [Fact]
    public void AttributeBag_CanInitialize_FromDictionary()
    {
        var dict = new Dictionary<string, object>
        {
            ["department"] = "finance",
            ["amount"] = 50000m
        };
        var attributes = new AttributeBag(dict);

        Assert.Equal(2, attributes.Count);
        Assert.Equal("finance", attributes["department"]);
        Assert.Equal(50000m, attributes["amount"]);
    }
}