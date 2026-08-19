# Multi-Tenancy

## Current model

Communities are selected by URL hash/ID and tenant records are stored in `community_kv` with a `community_id`. Individual residents, invoices, payments, expenses, visitors, and other entities live inside JSON values rather than independently policy-controlled rows. Protected Edge Functions are used when a custom session exists, but the client can fall back to direct Supabase reads. RLS and function authorization were not available for review.

Therefore the current tenant boundary is **not certified**.

## Required target model

- One immutable community identifier per tenant.
- A `community_memberships(user_id, community_id, role, status)` authorization source.
- A non-null `community_id` foreign key on every tenant-owned row.
- RLS enabled and forced where appropriate, with `SELECT`, `INSERT`, `UPDATE`, and `DELETE` policies separately reviewed.
- Policies derive access from authenticated identity and membership, never a URL hash or untrusted request field.
- Platform support access is time-bound, least-privilege, reason-coded, and audited.
- Service-role usage is limited to reviewed server functions; no service-role credential reaches the browser.

## Mandatory test matrix

For every tenant-owned table and every Edge Function, test anonymous, resident, staff/security, community-admin, platform-staff, and super-admin identities. Include same-tenant success and cross-tenant read/write/delete failure. Also test forged `community_id`, missing ID, inactive membership, role downgrade, stale token, bulk operations, exports, AI requests, backups, and payment endpoints.

A representative SQL/API test should create Community A and B, seed distinct marker rows, authenticate each role, and prove that A can never observe B's marker by row ID, filter, RPC, relationship, function body, cache, error message, report, or downloaded export.

## Migration order

1. Add authenticated users, communities, memberships, and audited platform-access grants.
2. Normalize invoices and payments first; dual-write and reconcile counts/totals.
3. Normalize owners/tenants and property membership.
4. Migrate operational modules in bounded batches.
5. Only after parity and negative isolation tests, remove KV/direct-access paths.

All schema and RLS changes are **REQUIRES MANUAL PRODUCTION APPROVAL**.
