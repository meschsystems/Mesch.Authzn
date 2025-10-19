using Xunit.Abstractions;

namespace Mesch.Authzn.Tests;
/// <summary>
/// Integration tests for complete scenarios.
/// </summary>
public class IntegrationTests
{
    private readonly ITestOutputHelper _output;

    public IntegrationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    [Fact]
    public async Task CompleteScenario_MultiTenantApplication()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:tenant-admin", r =>
            {
                r.Grant("invoice:*", new ScopeBag { ["tenant"] = "acme" });
                r.Grant("user:*", new ScopeBag { ["tenant"] = "acme" });
            })
            .AddRole("role:global-viewer", r =>
            {
                r.Grant("invoice:read");
            })
            .Assign("user:admin", "role:tenant-admin")
            .Assign("user:viewer", "role:global-viewer")
            .Build();

        // Tenant admin can manage invoices in their tenant
        var decision1 = await auth.Engine
            .For("user:admin")
            .On("invoice:create")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .EvaluateAsync();
        Assert.True(decision1.IsAllowed);
        _output.WriteLine("Tenant admin can create invoices in their tenant");

        // Tenant admin cannot manage invoices in other tenants
        var decision2 = await auth.Engine
            .For("user:admin")
            .On("invoice:create")
            .InScope(new ScopeBag { ["tenant"] = "other" })
            .EvaluateAsync();
        Assert.False(decision2.IsAllowed);
        _output.WriteLine("Tenant admin cannot create invoices in other tenants");

        // Global viewer can read invoices anywhere
        var decision3 = await auth.Engine
            .For("user:viewer")
            .On("invoice:read")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .EvaluateAsync();
        Assert.True(decision3.IsAllowed);
        _output.WriteLine("Global viewer can read invoices in any tenant");

        // Global viewer cannot write
        var decision4 = await auth.Engine
            .For("user:viewer")
            .On("invoice:write")
            .EvaluateAsync();
        Assert.False(decision4.IsAllowed);
        _output.WriteLine("Global viewer cannot write invoices");
    }

    [Fact]
    public async Task CompleteScenario_FinancialApprovalWorkflow()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:finance-manager", r =>
            {
                r.Grant(
                    "invoice:approve",
                    new ScopeBag { ["tenant"] = "acme" },
                    attrs =>
                    {
                        if (!attrs.ContainsKey("amount") || !attrs.ContainsKey("managerLevel"))
                        {
                            return false;
                        }
                        var amount = Convert.ToDecimal(attrs["amount"]);
                        var level = Convert.ToInt32(attrs["managerLevel"]);
                        return amount <= 50000 && level >= 2;
                    });
            })
            .AddRole("role:senior-manager", r =>
            {
                r.Grant(
                    "invoice:approve",
                    new ScopeBag { ["tenant"] = "acme" },
                    attrs =>
                    {
                        if (!attrs.ContainsKey("amount"))
                        {
                            return false;
                        }
                        var amount = Convert.ToDecimal(attrs["amount"]);
                        return amount <= 200000;
                    });
            })
            .Assign("user:manager", "role:finance-manager")
            .Assign("user:senior", "role:senior-manager")
            .Build();

        // Finance manager can approve small invoices
        var decision1 = await auth.Engine
            .For("user:manager")
            .On("invoice:approve")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .WithAttributes(new AttributeBag
            {
                ["amount"] = 30000m,
                ["managerLevel"] = 2
            })
            .EvaluateAsync();
        Assert.True(decision1.IsAllowed);
        _output.WriteLine("Finance manager approved $30k invoice");

        // Finance manager cannot approve large invoices
        var decision2 = await auth.Engine
            .For("user:manager")
            .On("invoice:approve")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .WithAttributes(new AttributeBag
            {
                ["amount"] = 100000m,
                ["managerLevel"] = 2
            })
            .EvaluateAsync();
        Assert.False(decision2.IsAllowed);
        _output.WriteLine("Finance manager denied $100k invoice");

        // Senior manager can approve large invoices
        var decision3 = await auth.Engine
            .For("user:senior")
            .On("invoice:approve")
            .InScope(new ScopeBag { ["tenant"] = "acme" })
            .WithAttributes(new AttributeBag
            {
                ["amount"] = 150000m
            })
            .EvaluateAsync();
        Assert.True(decision3.IsAllowed);
        _output.WriteLine("Senior manager approved $150k invoice");
    }

    [Fact]
    public async Task CompleteScenario_TemporaryAccessGrant()
    {
        var now = DateTimeOffset.UtcNow;
        var oneHourAgo = now.AddHours(-1);
        var oneHourFromNow = now.AddHours(1);

        var auth = AuthorizationBuilder.Create()
            .AddRole("role:temp-admin", r => r.Grant("system:*"))
            .Assign("user:contractor", "role:temp-admin", oneHourAgo, oneHourFromNow)
            .Build();

        // Access is currently valid
        var decision = await auth.Engine
            .For("user:contractor")
            .On("system:admin")
            .EvaluateAsync();
        Assert.True(decision.IsAllowed);
        _output.WriteLine("Temporary access is currently valid");

        // Simulate time passage (in real scenario, time would actually pass)
        _output.WriteLine("Access would expire after the NotAfter time");
    }

    [Fact]
    public async Task CompleteScenario_HierarchicalPermissions()
    {
        var auth = AuthorizationBuilder.Create()
            .AddRole("role:project-lead", r =>
            {
                r.Grant("project:task:*", new ScopeBag
                {
                    ["tenant"] = "acme",
                    ["project"] = "alpha"
                });
            })
            .AddRole("role:developer", r =>
            {
                r.Grant("project:task:read", new ScopeBag
                {
                    ["tenant"] = "acme",
                    ["project"] = "alpha"
                });
                r.Grant("project:task:update", new ScopeBag
                {
                    ["tenant"] = "acme",
                    ["project"] = "alpha"
                });
            })
            .Assign("user:lead", "role:project-lead")
            .Assign("user:dev", "role:developer")
            .Build();

        // Project lead has all task permissions via wildcard
        var decision1 = await auth.Engine
            .For("user:lead")
            .On("project:task:delete")
            .InScope(new ScopeBag
            {
                ["tenant"] = "acme",
                ["project"] = "alpha"
            })
            .EvaluateAsync();
        Assert.True(decision1.IsAllowed);
        _output.WriteLine("Project lead can delete tasks");

        // Developer cannot delete
        var decision2 = await auth.Engine
            .For("user:dev")
            .On("project:task:delete")
            .InScope(new ScopeBag
            {
                ["tenant"] = "acme",
                ["project"] = "alpha"
            })
            .EvaluateAsync();
        Assert.False(decision2.IsAllowed);
        _output.WriteLine("Developer cannot delete tasks");

        // Developer can read
        var decision3 = await auth.Engine
            .For("user:dev")
            .On("project:task:read")
            .InScope(new ScopeBag
            {
                ["tenant"] = "acme",
                ["project"] = "alpha"
            })
            .EvaluateAsync();
        Assert.True(decision3.IsAllowed);
        _output.WriteLine("Developer can read tasks");

        // More specific scope still works
        var decision4 = await auth.Engine
            .For("user:lead")
            .On("project:task:read")
            .InScope(new ScopeBag
            {
                ["tenant"] = "acme",
                ["project"] = "alpha",
                ["sprint"] = "sprint-1"
            })
            .EvaluateAsync();
        Assert.True(decision4.IsAllowed);
        _output.WriteLine("Project lead can access tasks in specific sprint");
    }

    [Fact]
    public async Task CompleteScenario_RuntimeRoleManagement()
    {
        var host = AuthorizationBuilder.Create().Build();

        // Add roles at runtime
        var adminRole = new Role("role:admin", "Administrator", new List<PermissionGrant>
        {
            new PermissionGrant("system:*")
        });
        host.AddRole(adminRole);
        _output.WriteLine("Added admin role at runtime");

        // Add assignment at runtime
        host.AddAssignment(new Assignment("user:newadmin", "role:admin"));
        _output.WriteLine("Added assignment at runtime");

        // Verify access
        var decision1 = await host.Engine
            .For("user:newadmin")
            .On("system:config")
            .EvaluateAsync();
        Assert.True(decision1.IsAllowed);
        _output.WriteLine("New admin has system access");

        // Revoke access
        host.Revoke("user:newadmin", "role:admin");
        _output.WriteLine("Revoked admin access");

        // Verify revocation
        var decision2 = await host.Engine
            .For("user:newadmin")
            .On("system:config")
            .EvaluateAsync();
        Assert.False(decision2.IsAllowed);
        _output.WriteLine("Admin access successfully revoked");
    }
}