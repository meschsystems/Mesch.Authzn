namespace Mesch.Authzn.Tests;
/// <summary>
/// Tests for in-memory stores.
/// </summary>
public class InMemoryStoresTests
{
    [Fact]
    public async Task InMemoryRoleStore_ReturnsNull_WhenRoleNotFound()
    {
        var store = new InMemoryRoleStore();

        var role = await store.GetRoleAsync("role:nonexistent");

        Assert.Null(role);
    }

    [Fact]
    public async Task InMemoryRoleStore_ReturnsRole_WhenExists()
    {
        var store = new InMemoryRoleStore();
        var role = new Role("role:admin", "Admin", new List<PermissionGrant>());
        store.Add(role);

        var retrieved = await store.GetRoleAsync("role:admin");

        Assert.NotNull(retrieved);
        Assert.Equal("role:admin", retrieved.Id.Value);
    }

    [Fact]
    public async Task InMemoryAssignmentStore_ReturnsEmpty_WhenNoAssignments()
    {
        var store = new InMemoryAssignmentStore();

        var assignments = await store.GetAssignmentsForPrincipalAsync("user:1");

        Assert.Empty(assignments);
    }

    [Fact]
    public async Task InMemoryAssignmentStore_ReturnsAssignments_ForPrincipal()
    {
        var store = new InMemoryAssignmentStore();
        var assignment1 = new Assignment("user:1", "role:admin");
        var assignment2 = new Assignment("user:1", "role:editor");
        var assignment3 = new Assignment("user:2", "role:viewer");
        store.Add(assignment1);
        store.Add(assignment2);
        store.Add(assignment3);

        var assignments = await store.GetAssignmentsForPrincipalAsync("user:1");

        Assert.Equal(2, assignments.Count);
        Assert.All(assignments, a => Assert.Equal("user:1", a.Principal.Value));
    }

    [Fact]
    public async Task InMemoryAssignmentStore_Revoke_MarksAssignmentAsRevoked()
    {
        var store = new InMemoryAssignmentStore();
        var assignment = new Assignment("user:1", "role:admin");
        store.Add(assignment);

        store.Revoke("user:1", "role:admin");

        var assignments = await store.GetAssignmentsForPrincipalAsync("user:1");
        Assert.Single(assignments);
        Assert.True(assignments[0].Revoked);
    }
}