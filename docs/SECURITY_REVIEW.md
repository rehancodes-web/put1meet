# Security Review

Assessment date: 2026-08-20  
Scope: repository snapshot, GitHub repository settings visible to the reviewer, public DNS/live application behavior, and the Supabase evidence available in the connected workspace.

## Verdict

**Payment processing is materially hardened, but the full application is not yet safe for unrestricted production use with real resident and credential data.**

The production Supabase project (`oaspvvummczhcawzlfua`) was inspected directly on 2026-08-20. Payment authority and replay controls described below are deployed. Supabase's production security advisor reports zero findings, and the sensitive KV and payment tables grant no access to `anon` or `authenticated`. Custom authentication, broad CORS on legacy functions, stored-XSS exposure, and whole-document KV writes remain open work.

## Remediation status (2026-08-20)

- Deployed authoritative payment order creation: the server loads the invoice, tenant, owner, and outstanding amount rather than trusting browser values.
- Deployed signed webhook validation, constant-time signature comparison, captured-status/currency/amount checks, and idempotent event/payment claims.
- Added server-only `payment_orders` and `payment_events` ledgers with forced RLS, explicit deny policies, uniqueness constraints, and revoked client grants.
- Forced RLS and explicit client-deny policies on `platform_kv` and `community_kv`; direct grants remain limited to `postgres` and `service_role`.
- Restricted the payment order endpoint to approved production origins and an authenticated community session.
- Replaced plaintext database session tokens with SHA-256 digests across login, MFA, bootstrap, write, AI, payment, and password-change paths; all existing production sessions/challenges were already zero at rollout.
- Replaced non-cryptographic OTP generation and made community reset-OTP consumption atomic to prevent concurrent replay.
- Removed wildcard CORS and enforced approved origins plus POST-only handling across auth, bootstrap, privileged write, AI, and password-change functions.
- Forced RLS and revoked client grants on all session, MFA-challenge, and password-reset tables.
- Added an atomic server-side authentication rate limiter for login and reset-request endpoints, with client-deny RLS and service-role-only execution.
- Added centralized HTML sanitization for alert rendering and pinned browser dependency versions locally.
- Live negative tests return HTTP 400 for an order request without a community session and for a forged webhook signature.

## Top risks

| Severity | Finding | Evidence and impact | Required action |
|---|---|---|---|
| Critical | Tenant isolation cannot be verified | Domain data is embedded in `community_kv` JSON. The anonymous direct-read fallback was removed in this review, but deployed RLS and Edge Function authorization remain unavailable. | Normalize tenant-owned data; inspect and test RLS in the actual project. **REQUIRES MANUAL PRODUCTION APPROVAL.** |
| Resolved (2026-08-20) | Browser-controlled payment authority and webhook replay | Server now derives the authoritative invoice balance and binds it to a unique Razorpay order; webhook processing verifies signature and bound values and claims unique event/payment IDs. | Monitor failed events and complete a documented refund/dispute reconciliation runbook. |
| Critical | Password-reset backend remains unverified | Client-side OTP preview consumption/storage/display was removed. The absent Edge Function must still stop returning preview values, deliver OTP server-side, rate-limit attempts, and prevent enumeration. | Fix and verify deployed functions; invalidate old reset requests/sessions. **REQUIRES MANUAL PRODUCTION APPROVAL.** |
| High | Existing TOTP secrets may have been disclosed | QR generation is now local in the browser, but earlier setup sent the full `otpauth` URI to a third-party QR service. | Rotate secrets provisioned through the earlier flow and verify server-side TOTP protections. |
| High | Account activation is incomplete | Password fields were removed from welcome-email payloads. The current custom-auth backend lacks a reviewed single-use activation-link flow. | Implement short-lived server-generated activation links; never transmit a password. |
| High | Weak legacy password hashing | Password verification still uses static-salt SHA-256 in the custom auth store. Session-token storage is now digest-only and endpoint rate limiting is active, but password hashes remain non-adaptive. | Migrate credentials to Supabase Auth or Argon2id/bcrypt with unique salts; force password resets after migration. |
| High | Mutable/non-independent audit and backup data | Activity logs and snapshots are ordinary JSON in the same tenant KV store and can be overwritten/deleted through the same path. | Add append-only server audit events and independent encrypted backups/PITR. |
| High | Stored-XSS attack surface | One file has extensive inline handlers and hundreds of `innerHTML` assignments. Escaping exists but is not universal. CSP permits inline script. | Introduce safe DOM rendering, centralized sanitization, Trusted Types where feasible, and XSS tests. |
| High | Backend source and deployment drift | Deployed Edge Function sources have now been recovered into the working tree, but the hardened working tree has not yet been committed and the duplicate Vercel deployment state remains. | Commit reviewed backend/IaC and consolidate production deployment. |
| Medium | Whole-document asynchronous writes | Entire arrays are overwritten without awaited acknowledgement/version checks. Concurrent users can silently lose financial or resident changes. | Normalize tables and use transactions/optimistic concurrency. |
| Medium | Supply-chain reproducibility incomplete | CDN dependency versions are pinned locally, but there is no lockfile, integrity metadata, or automated dependency/security checking. | Bundle dependencies with a package manifest/lockfile, add integrity where applicable, and enable CI scanning. |

## Authentication and authorization

- Authentication is custom, not demonstrably Supabase Auth. Session tokens are stored in `sessionStorage`; a 20-minute client inactivity timeout is present. Client expiry is useful UX but cannot replace server expiry/revocation.
- Role checks in the browser include platform super admin/staff and community roles. They hide UI; they do not prove server enforcement.
- Login may iterate communities when no hash is present, multiplying authentication requests and enabling timing/enumeration or brute-force amplification.
- No evidence was available for password policy, rate limiting, lockout, token entropy, hashing parameters, server token expiry, refresh/revocation, MFA replay protection, or session invalidation.

## Tenant-isolation review

The browser consistently supplies `_cid`, but client scoping is not a security guarantee. Required negative tests against the production-equivalent backend:

1. Community A resident cannot read or mutate Community B KV rows using a changed hash/body/header.
2. Community A admin cannot obtain B data through bootstrap, write, AI, Razorpay, backup, support, or report endpoints.
3. Platform staff roles have explicit, least-privilege community scopes; only an audited super-admin path can cross tenants.
4. Anonymous/publishable-key requests cannot select, insert, update, or delete tenant or platform data.
5. Every tenant-owned table rejects null or forged `community_id`; policies derive tenant membership from authenticated claims/membership tables.

Until these pass in CI and staging against the actual schema and policies, isolation is **unverified**.

## Secrets and configuration

No service-role key, database password, JWT secret, private key, SMTP password, WhatsApp token, or hard-coded Razorpay secret was found in the snapshot. The Supabase publishable/anon credentials and EmailJS public key are expected to be visible in a browser, but must have origin/rate restrictions and least-privilege server policies. A legacy anon JWT is duplicated in the client and should be removed after compatibility verification.

| Value | Expected location | Browser exposure |
|---|---|---|
| Supabase URL + publishable key | Public runtime config | Allowed; never sufficient for authorization |
| Supabase service role/JWT secret/DB password | Supabase/Vercel encrypted secrets only | Forbidden |
| Razorpay Key ID | Client response for a server-created order | Allowed |
| Razorpay Key Secret/webhook secret | Server encrypted secrets only | Forbidden |
| Email provider private key | Server encrypted secrets only | Forbidden |
| WhatsApp/SMS credentials | Server encrypted secrets only | Forbidden |
| AI provider key | Server encrypted secrets only | Forbidden |

Repository history could not be cloned with Git metadata, so historical secret exposure remains unassessed. Rotate any secret ever committed, even if later deleted.

## Browser and network controls

The HTML includes a meta CSP and no-store directives. The added `vercel.json` moves compatible controls to response headers and adds HSTS, MIME sniffing protection, frame denial, and a permissions policy. The CSP must temporarily retain `'unsafe-inline'` because the current application depends on inline script and handlers; it is hardening, not an XSS cure. Validate Razorpay checkout after deployment.

## Required approval gates

The following must not be applied blindly to production: RLS/policy changes, authentication migration, data-model migration, payment/webhook changes, secret rotation, deletion of fallback paths, DNS/project consolidation, backup retention changes, and production data migration. Each needs staging verification, a backup, rollback instructions, named approvers, and post-deployment tests.
