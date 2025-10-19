# Mesch.Authzn

A lightweight, role-based access control (RBAC) with optional ABAC (attribute-based access control) authorization library for .NET applications.

## Overview

Mesch.Authzn provides a drop-in authorization engine that answers a single question: "Can this principal perform this action in this scope, right now?" The library ships with in-memory stores for immediate use and exposes interfaces for custom persistence implementations.

The authorization model is purely additive. Permissions are granted through roles, and roles are assigned to principals. No deny rules or negative permissions are supported.

## Installation

```bash
dotnet add package Mesch.Authzn
```

## Core Concepts

### Principal

An actor in the system, represented by a `PrincipalId`. Principals can be users, services, or groups. All identity metadata (name, email, department) is maintained externally in the identity system.

### Role

A reusable definition of authority. Roles contain permission grants and are stable, timeless definitions. A role does not change based on time or context.

### Permission

A permission consists of a **resource** and an **action**, expressed as `resource:action`. The library supports both simple and hierarchical resources:

- Simple: `documents:read`, `invoices:write`, `users:delete`
- Hierarchical: `project:task:read`, `api:v1:endpoints:create`

The rightmost segment after the final colon is the action; everything before it is the resource.

Wildcard actions are supported using `*`:
- `documents:*` - All actions on documents
- `project:task:*` - All actions on project tasks
- `*:*` (or just `*`) - All actions on all resources

Reading permissions right-to-left provides natural semantics:
- `project:task:read` - "For project, when dealing with task, may read"
- `api:v1:user:update` - "For api, in v1, when dealing with user, may update"

### Scope

A key-value collection that constrains where a permission applies. Common scope keys include `tenant`, `project`, or `resource`. An empty scope applies universally.

### Assignment

The link between a principal and a role. Assignments are the only time-varying element in the authorization model. An assignment can:

- Start in the future via `NotBefore`
- Expire via `NotAfter`
- Be revoked via the `Revoked` flag

### Authorization Decision

The result of an evaluation. Contains:

- `IsAllowed` - Boolean indicating whether access is granted
- `DenyReason` - Enumeration specifying why access was denied
- `MatchedRole` - The role that granted permission (if allowed)
- `MatchedPermission` - The specific permission that was matched (if allowed)

## Authorization Rule

A principal may perform an action if they hold an active assignment to a role that grants the required permission in the requested scope, and any attribute-based conditions evaluate to true.

## Deny Reasons

The `DenyReason` enumeration provides diagnostic information:

- `None` - Access allowed
- `NoAssignments` - Principal has no role assignments
- `NoMatchingPermission` - Principal has roles, but none grant the requested permission
- `ScopeMismatch` - Permission exists but scope does not match
- `AssignmentNotActive` - Assignment is expired, not yet valid, or revoked
- `AttributeEvaluationFailed` - ABAC condition returned false or threw an exception

## Basic Usage

### Simple Authorization

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:reader", r => r.Grant("invoice:read"))
    .Assign("user:42", "role:reader")
    .Build();

var decision = await auth.Engine
    .For("user:42")
    .On("invoice:read")
    .EvaluateAsync();

if (decision.IsAllowed)
{
    // Proceed with action
}
```

### Wildcard Permissions

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:admin", r => r.Grant("invoice:*"))
    .Assign("user:1", "role:admin")
    .Build();

// Matches invoice:read, invoice:write, invoice:delete, etc.
var decision = await auth.Engine
    .For("user:1")
    .On("invoice:delete")
    .EvaluateAsync();
```

### Scoped Permissions

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:tenant-admin", r =>
        r.Grant("invoice:*", new ScopeBag { ["tenant"] = "acme" }))
    .Assign("user:99", "role:tenant-admin")
    .Build();

// Allowed - scope matches
var decision1 = await auth.Engine
    .For("user:99")
    .On("invoice:read")
    .InScope(new ScopeBag { ["tenant"] = "acme" })
    .EvaluateAsync();

// Denied - scope mismatch
var decision2 = await auth.Engine
    .For("user:99")
    .On("invoice:read")
    .InScope(new ScopeBag { ["tenant"] = "other" })
    .EvaluateAsync();
```

### Hierarchical Resources

Resources can be hierarchical using multiple colon-separated segments:

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:project-lead", r =>
        r.Grant("project:task:*", new ScopeBag
        {
            ["tenant"] = "acme",
            ["project"] = "alpha"
        }))
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

// Project lead can delete tasks (via wildcard)
var decision1 = await auth.Engine
    .For("user:lead")
    .On("project:task:delete")
    .InScope(new ScopeBag
    {
        ["tenant"] = "acme",
        ["project"] = "alpha"
    })
    .EvaluateAsync();
// Result: Allowed

// Developer cannot delete tasks (only read and update)
var decision2 = await auth.Engine
    .For("user:dev")
    .On("project:task:delete")
    .InScope(new ScopeBag
    {
        ["tenant"] = "acme",
        ["project"] = "alpha"
    })
    .EvaluateAsync();
// Result: Denied
```

### Scope Hierarchies

Granted scopes apply to equal or more specific requested scopes:

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:project-admin", r =>
        r.Grant("task:manage", new ScopeBag
        {
            ["tenant"] = "acme",
            ["project"] = "alpha"
        }))
    .Assign("user:200", "role:project-admin")
    .Build();

// Allowed - more specific scope
var decision = await auth.Engine
    .For("user:200")
    .On("task:manage")
    .InScope(new ScopeBag
    {
        ["tenant"] = "acme",
        ["project"] = "alpha",
        ["sprint"] = "sprint-1"
    })
    .EvaluateAsync();
```

### Attribute-Based Access Control (ABAC)

Permission grants can include runtime conditions:

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:approver", r =>
        r.Grant(
            "invoice:approve",
            new ScopeBag { ["tenant"] = "acme" },
            attrs =>
            {
                var amount = Convert.ToDecimal(attrs["amount"]);
                var level = Convert.ToInt32(attrs["managerLevel"]);
                return level >= 3 && amount <= 100000;
            }))
    .Assign("user:77", "role:approver")
    .Build();

var decision = await auth.Engine
    .For("user:77")
    .On("invoice:approve")
    .InScope(new ScopeBag { ["tenant"] = "acme" })
    .WithAttributes(new AttributeBag
    {
        ["amount"] = 50000m,
        ["managerLevel"] = 3
    })
    .EvaluateAsync();
```

### Time-Bounded Assignments

```csharp
var startDate = DateTimeOffset.UtcNow;
var endDate = startDate.AddDays(30);

var auth = AuthorizationBuilder.Create()
    .AddRole("role:contractor", r => r.Grant("project:read"))
    .Assign("user:50", "role:contractor", notBefore: startDate, notAfter: endDate)
    .Build();
```

### Revocation

```csharp
var auth = AuthorizationBuilder.Create()
    .AddRole("role:editor", r => r.Grant("document:edit"))
    .Assign("user:25", "role:editor")
    .Build();

// Later, revoke access
auth.Revoke("user:25", "role:editor");
```

## Dependency Injection

### Registration

```csharp
services.AddAuthorizationEngine(builder =>
{
    builder
        .AddRole("role:admin", r => r.Grant("system:*"))
        .AddRole("role:reader", r => r.Grant("system:read"))
        .Assign("user:1", "role:admin");
});
```

### Usage in Services

```csharp
public class InvoiceService
{
    private readonly IAuthorizationEngine _authEngine;

    public InvoiceService(IAuthorizationEngine authEngine)
    {
        _authEngine = authEngine;
    }

    public async Task<Invoice> GetInvoiceAsync(string principalId, string invoiceId)
    {
        var decision = await _authEngine
            .For(principalId)
            .On("invoice:read")
            .InScope(new ScopeBag { ["tenant"] = GetTenantForInvoice(invoiceId) })
            .EvaluateAsync();

        if (!decision.IsAllowed)
        {
            throw new UnauthorizedAccessException($"Access denied: {decision.DenyReason}");
        }

        return await LoadInvoiceAsync(invoiceId);
    }
}
```

## Custom Persistence

The library provides `IRoleStore` and `IAssignmentStore` interfaces for custom persistence implementations.

### Interface Definitions

```csharp
public interface IRoleStore
{
    Task<Role?> GetRoleAsync(RoleId id, CancellationToken ct = default);
}

public interface IAssignmentStore
{
    Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
        PrincipalId principal, CancellationToken ct = default);
}
```

### Entity Framework Core Example

```csharp
public class EfCoreRoleStore : IRoleStore
{
    private readonly AuthorizationDbContext _context;

    public EfCoreRoleStore(AuthorizationDbContext context)
    {
        _context = context;
    }

    public async Task<Role?> GetRoleAsync(RoleId id, CancellationToken ct = default)
    {
        var entity = await _context.Roles
            .Include(r => r.Grants)
            .FirstOrDefaultAsync(r => r.Id == id.Value, ct);

        if (entity == null)
        {
            return null;
        }

        var grants = entity.Grants.Select(g => new PermissionGrant(
            g.Permission,
            JsonSerializer.Deserialize<ScopeBag>(g.ScopeJson),
            null // Conditions cannot be persisted
        )).ToList();

        return new Role(entity.Id, entity.Name, grants);
    }
}

public class EfCoreAssignmentStore : IAssignmentStore
{
    private readonly AuthorizationDbContext _context;

    public EfCoreAssignmentStore(AuthorizationDbContext context)
    {
        _context = context;
    }

    public async Task<IReadOnlyList<Assignment>> GetAssignmentsForPrincipalAsync(
        PrincipalId principal, CancellationToken ct = default)
    {
        var entities = await _context.Assignments
            .Where(a => a.PrincipalId == principal.Value)
            .ToListAsync(ct);

        return entities.Select(e => new Assignment(
            e.PrincipalId,
            e.RoleId,
            e.NotBefore,
            e.NotAfter
        )).ToList();
    }
}
```

### Registration with Custom Stores

```csharp
services.AddDbContext<AuthorizationDbContext>(options =>
    options.UseSqlServer(connectionString));

services.AddSingleton<IRoleStore, EfCoreRoleStore>();
services.AddSingleton<IAssignmentStore, EfCoreAssignmentStore>();

services.AddAuthorizationEngine(
    serviceProvider.GetRequiredService<IRoleStore>(),
    serviceProvider.GetRequiredService<IAssignmentStore>());
```

## Runtime Management

The `AuthorizationHost` provides convenience methods for in-memory store manipulation:

```csharp
var host = AuthorizationBuilder.Create().Build();

// Add role at runtime
var newRole = new Role("role:analyst", "Data Analyst", new List<PermissionGrant>
{
    new PermissionGrant("report:read"),
    new PermissionGrant("report:export")
});
host.AddRole(newRole);

// Add assignment at runtime
host.AddAssignment(new Assignment("user:new", "role:analyst"));

// Revoke assignment at runtime
host.Revoke("user:old", "role:analyst");
```

These methods only work with `InMemoryRoleStore` and `InMemoryAssignmentStore`. They throw `InvalidOperationException` when custom stores are used.

## Architecture

### Evaluation Flow

1. Retrieve all assignments for the principal
2. Filter assignments to only those active at the current time
3. For each active assignment:
   - Retrieve the role definition
   - Check each permission grant in the role:
     - Match permission (exact or wildcard)
     - Match scope (granted scope must be subset of requested scope)
     - Evaluate ABAC condition if present
   - Return allowed on first match
4. If no matches found, determine appropriate deny reason

### Permission Matching

Permissions are matched by comparing resource and action components separately.

Exact match:
```
Granted: "invoice:read"
Requested: "invoice:read"
Result: Match (resource="invoice" matches, action="read" matches)
```

Wildcard action:
```
Granted: "invoice:*"
Requested: "invoice:read"
Result: Match (resource="invoice" matches, action="*" matches anything)
```

Wildcard resource and action:
```
Granted: "*" (equivalent to "*:*")
Requested: "invoice:read"
Result: Match (both wildcards match anything)
```

Hierarchical resource match:
```
Granted: "project:task:*"
Requested: "project:task:delete"
Result: Match (resource="project:task" matches, action="*" matches "delete")
```

No match - different resources:
```
Granted: "invoice:*"
Requested: "project:read"
Result: No match (resource "invoice" != "project")
```

No match - different actions:
```
Granted: "invoice:read"
Requested: "invoice:delete"
Result: No match (action "read" != "delete")
```

### Scope Matching

All keys in the granted scope must exist in the requested scope with matching values. Additional keys in the requested scope are permitted.

```
Granted: { "tenant": "acme" }
Requested: { "tenant": "acme", "project": "alpha" }
Result: Match
```

```
Granted: { "tenant": "acme", "project": "alpha" }
Requested: { "tenant": "acme" }
Result: No match (missing required key "project")
```

### ABAC Evaluation

Conditions are evaluated after permission and scope matching. If a condition throws an exception or returns false, the grant is not applied and evaluation continues with the next grant. If no grants match after condition evaluation, `DenyReason.AttributeEvaluationFailed` is returned.

## Design Constraints

### Limitations

- No deny rules or negative permissions
- No direct permissions on principals (all permissions flow through roles)
- ABAC conditions cannot be persisted (they are code-based delegates)
- No built-in audit logging
- No permission inheritance or role hierarchies
- No query language or DSL for permission expressions

### Performance Considerations

- In-memory stores perform linear scans
- Each authorization check loads all assignments for a principal
- Each assignment requires a role lookup
- Consider caching role definitions in custom stores
- Consider indexing principal assignments in custom stores

## License

MIT