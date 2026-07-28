# ADR-0003: Shared-schema multi-tenancy with discriminator plus row-level security

- **Status:** Accepted
- **Date:** 2026-07-27
- **Deciders:** Platform architecture, Security

## Context

The platform is multi-tenant SaaS and also ships on-premises. Tenant data is unusually sensitive: it is
a catalogue of every unfixed vulnerability in the customer's applications. A cross-tenant read is not a
privacy incident, it is an existential product failure.

Tenant counts are expected in the thousands with a heavy skew — a few very large enterprises alongside
many small teams.

## Decision

**Shared schema, shared database, `organization_id` discriminator on every tenant-owned table**, with
three independent enforcement layers:

1. **Repository layer (primary).** All tenant data access goes through `TenantScopedRepository`, which
   takes the organization id in its constructor and injects the predicate into every query. There is
   no public method on a tenant-scoped repository that produces an unfiltered query.
2. **PostgreSQL row-level security (defence in depth).** Every tenant table has RLS enabled and
   **forced**, with a policy on `current_setting('app.current_organization_id')`. The application sets
   this GUC transaction-locally at transaction start from the authenticated principal. A repository
   bug therefore returns zero rows rather than another tenant's rows.

   Two consequences that are easy to get wrong and are therefore called out here:

   - **`FORCE ROW LEVEL SECURITY` is mandatory.** Without it the table owner bypasses the policy, and
     the table owner is usually the application role.
   - **The application must not connect as a superuser.** Superusers bypass RLS unconditionally, even
     with `FORCE`. `scripts/postgres/app-role.sql` creates the least-privilege role; the API logs a
     warning in development and refuses to start in staging or production when its role is a
     superuser; the test suite creates and uses a `NOSUPERUSER` role so the isolation tests prove
     something.

   A narrow, audited escape hatch (`app.rls_bypass`) exists for the two statements that must run
   before a tenant is known — resolving which organizations a user may sign in to, and looking up an
   API key by its public prefix. Both raise the flag around a single statement and lower it
   immediately; both return no tenant-owned data.
3. **Test layer (verification).** A generated cross-tenant suite calls every route as tenant B using
   tenant A's resource identifiers and asserts `404`. New routes without coverage fail the suite.

Platform-admin operations use a separate database role that bypasses RLS, reachable only through
explicitly audited code paths that log to the audit chain.

Very large enterprises requiring physical separation are served by a dedicated single-tenant
deployment of the whole stack, not by a schema-per-tenant variant of the shared deployment.

## Alternatives considered

| Option | Why not |
|---|---|
| Schema per tenant | Migration time scales with tenant count; connection-pool pressure; thousands of schemas makes routine DDL an operations project |
| Database per tenant | Strongest isolation, but the operational cost at thousands of tenants is prohibitive, and cross-tenant analytics (rule quality, benchmark data) becomes impossible |
| Discriminator only, no RLS | One missing `WHERE` clause is a catastrophic breach. The cost of RLS is a few percent of query time; the cost of the alternative is the company |
| RLS only, no repository enforcement | Relies on the GUC always being set; a background job that forgets it would see everything |

## Consequences

### Positive
- One migration path, one connection pool, straightforward operations at scale.
- Two independent controls must both fail for a cross-tenant read to occur.
- Cross-tenant aggregate analytics remain possible through the audited admin role.

### Negative
- Every query pays the RLS predicate cost; mitigated by making `organization_id` the leading column of
  every composite index.
- Noisy-neighbour risk on shared resources; mitigated by per-tenant quotas and query cost budgets.
- Developers must remember that "get by id" is always "get by id **and** organization".

### Neutral
- The on-premises deployment runs the same code with a single organization.

## Compliance

- Tenant-scoped repositories are constructed with an organization id and expose no method that can
  produce an unscoped query; they are unreachable until `bind_tenant()` has been called, and touching
  one before that raises `TenantNotBoundError`.
- `tests/security/test_tenant_isolation.py` attacks both layers: through the API (cross-tenant reads,
  writes, deletes, role assignment and agent access must all return `404`) and directly against the
  database with raw SQL that carries no tenant predicate at all.
- The suite connects as a `NOSUPERUSER` role, so the RLS assertions are meaningful.
- The cross-tenant isolation suite is a required CI job.

### Bugs this arrangement has already caught

During Phase 2 implementation, RLS rejected an `INSERT` into `licenses` that happened *before*
`bind_tenant()` in the registration use case. The repository layer alone would have accepted it. That
is the second control doing exactly its job.
