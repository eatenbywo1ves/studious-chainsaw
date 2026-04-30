# ADR-002: PostgreSQL Row-Level Security for Multi-Tenancy

**Status**: Accepted
**Date**: 2024-09-18
**Deciders**: Architecture Team, Security Lead, Database Team
**Technical Story**: Implement secure multi-tenant data isolation

---

## Context

The SaaS Platform must support multiple organizations (tenants) with complete data isolation. Each tenant's data must be invisible and inaccessible to other tenants, even if application code has bugs.

### Problem Statement

Implement multi-tenant data isolation that is secure, performant, and cannot be bypassed by application-layer bugs.

### Driving Forces

- **Security**: Tenant data must never leak to other tenants
- **Compliance**: GDPR, SOC 2 require demonstrable data isolation
- **Performance**: Isolation mechanism must not significantly impact query performance
- **Simplicity**: Developers should not need to remember to add tenant filters

### Constraints

- Must support 1,000+ tenants
- Query latency impact must be <10%
- Must work with existing PostgreSQL infrastructure
- Must be auditable for compliance

---

## Decision

**We will use PostgreSQL Row-Level Security (RLS) to enforce multi-tenant data isolation at the database level.**

### Implementation

1. **RLS Policies**: Every table with tenant data has RLS enabled with policies based on `org_id`

2. **Session Context**: Application sets `app.current_org_id` from JWT claims before each request

3. **Automatic Enforcement**: Database rejects any query that would access another tenant's data

### Key Implementation Details

```sql
-- Enable RLS on all tenant tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;

-- Create isolation policy
CREATE POLICY tenant_isolation ON users
    FOR ALL
    USING (org_id = current_setting('app.current_org_id')::uuid);

-- Application sets context from JWT
SET app.current_org_id = 'org-uuid-from-jwt';
```

---

## Consequences

### Positive (Benefits)

- ✅ **Database-Enforced**: Impossible to bypass at application layer
- ✅ **Audit-Friendly**: Policies are visible, version-controlled, and testable
- ✅ **Transparent to App**: No code changes needed after initial setup
- ✅ **Performance**: Native PostgreSQL feature, optimized by query planner
- ✅ **Compliance**: Easy to demonstrate isolation for auditors

### Negative (Trade-offs)

- ❌ **PostgreSQL Lock-in**: RLS is PostgreSQL-specific (no MySQL/SQLite)
- ❌ **Context Management**: Must set `app.current_org_id` on every connection
- ❌ **Admin Queries**: Superuser must explicitly bypass RLS for admin operations
- ❌ **Debugging**: Can be confusing when queries return empty (RLS filtering)

### Neutral

- ℹ️ Requires careful connection pool management (context per request)
- ℹ️ Migration required to add `org_id` to all tenant tables

---

## Alternatives Considered

### Alternative 1: Application-Layer Filtering

**Description**: Add `WHERE org_id = :org_id` to every query in application code.

**Pros**:
- Database-agnostic
- No special PostgreSQL features needed
- Developers have full control

**Cons**:
- Easy to forget (human error)
- One bug can expose all tenant data
- Hard to audit (spread across codebase)
- No guarantee of isolation

**Why Rejected**: Security risk too high. A single missing filter clause could expose all tenant data.

### Alternative 2: Separate Databases per Tenant

**Description**: Create a separate PostgreSQL database for each tenant.

**Pros**:
- Complete physical isolation
- Easy to backup/restore per tenant
- No query performance impact
- Clear compliance story

**Cons**:
- Operational nightmare at scale (1,000+ databases)
- Connection management complexity
- Schema migrations must run on all databases
- High infrastructure cost

**Why Rejected**: Does not scale to 1,000+ tenants. Operational overhead too high.

### Alternative 3: Schema per Tenant

**Description**: Create a separate PostgreSQL schema for each tenant within one database.

**Pros**:
- Good isolation within one database
- Can use `search_path` for tenant context
- Easier than separate databases

**Cons**:
- Still scales poorly (1,000+ schemas)
- Schema migrations still complex
- Connection pooling challenges
- Query joins across schemas are awkward

**Why Rejected**: Still doesn't scale well, and migrations are complex.

---

## Implementation Plan

1. **Phase 1** (Week 1): Add `org_id` column to all tenant tables, create RLS policies
2. **Phase 2** (Week 2): Implement middleware to set `app.current_org_id` from JWT
3. **Phase 3** (Week 3): Test isolation with integration tests, security review
4. **Phase 4** (Week 4): Deploy to staging, penetration testing

### Success Criteria

- [x] All tenant tables have RLS enabled
- [x] No query returns data from other tenants
- [x] Performance impact <10% on p95 latency
- [x] Security team sign-off

### Risks

| Risk | Impact | Probability | Mitigation |
|------|--------|------------|------------|
| RLS bypassed accidentally | Critical | Low | Automated tests, code review |
| Performance regression | Medium | Low | Query plan analysis, benchmarking |
| Context not set | High | Medium | Middleware enforcement, connection validation |

---

## Related Decisions

- [ADR-001: FastAPI over Flask](001-fastapi-over-flask.md)
- [ADR-003: JWT RS256 for Authentication](003-jwt-rs256-asymmetric.md)

---

## References

- [PostgreSQL RLS Documentation](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Multi-Tenancy with RLS](https://aws.amazon.com/blogs/database/multi-tenant-data-isolation-with-postgresql-row-level-security/)
- [Citus Data: RLS Best Practices](https://www.citusdata.com/blog/2018/04/04/implementing-multi-tenancy/)

---

**Last Updated**: 2024-10-15
**Review Date**: 2025-01-15
