namespace Mesch.Authzn.Tests;

/// <summary>
/// Tests for custom store implementations.
/// </summary>
public class CustomStoreTests
{

    [Fact]
    public async Task CustomStore_CanBeUsed_WithBuilder()
    {
        var roleStore = new TestCustomRoleStore();
        var assignmentStore = new TestCustomAssignmentStore();

        var auth = AuthorizationBuilder.Create()
            .UseRoleStore(roleStore)
            .UseAssignmentStore(assignmentStore)
            .Build();

        Assert.NotNull(auth);
        Assert.NotNull(auth.Engine);
    }

    [Fact]
    public async Task CustomStore_ThrowsException_WhenCallingInMemoryMethods()
    {
        var roleStore = new TestCustomRoleStore();
        var assignmentStore = new TestCustomAssignmentStore();

        var host = AuthorizationBuilder.Create()
            .UseRoleStore(roleStore)
            .UseAssignmentStore(assignmentStore)
            .Build();

        Assert.Throws<InvalidOperationException>(() =>
        {
            host.AddRole(new Role("role:test", "Test", []));
        });

        Assert.Throws<InvalidOperationException>(() =>
        {
            host.AddAssignment(new Assignment("user:1", "role:test"));
        });

        Assert.Throws<InvalidOperationException>(() =>
        {
            host.Revoke("user:1", "role:test");
        });
    }

    private class TestCustomRoleStore : IRoleStore
    {
        public Task<Role?> GetRoleAsync(RoleId id, CancellationToken ct = default)
        {
            return Task.FromResult<Role?>(null);
        }
    }

    private class TestCustomAssignmentStore : IAssignmentStore
    {
        public Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
            PrincipalId principal, CancellationToken ct = default)
        {
            return Task.FromResult<IReadOnlyList<Assignment>>([]);
        }
    }
}