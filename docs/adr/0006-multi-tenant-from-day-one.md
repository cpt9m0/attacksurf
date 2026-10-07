# 0006. Multi-tenant schema from day one

- Status: accepted
- Date: 2026-10-07

## Context
The MVP is effectively single-user, but may become a SaaS. Retrofitting tenancy is a costly,
risky migration.

## Decision
`Org` + `Membership` from the start. Every tenant-owned row has a NOT NULL, indexed `org_id`; all
queries are scoped through a helper. Each endpoint gets a tenant-isolation test.

## Consequences
- Slight extra effort per feature.
- Postgres Row-Level Security can be added later as defense in depth.
