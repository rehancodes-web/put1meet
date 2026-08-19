# Production Readiness

## Decision

**NO-GO for real production data as of 2026-08-18. Score: 32/100.**

| Area | Score | Reason |
|---|---:|---|
| Architecture/reproducibility | 4/15 | Single 1 MB HTML file; no build, lockfile, backend source, migrations, or IaC |
| Security/authentication | 5/20 | Serious reset/MFA/password risks; server enforcement unavailable for review |
| Tenant isolation | 3/20 | KV model and direct fallback; actual RLS unavailable |
| Payments/data integrity | 5/15 | Approval workflow exists, but server verification/webhooks/idempotency unavailable |
| Reliability/recovery | 4/15 | Same-database browser snapshots; no demonstrated PITR/restore test |
| Delivery/operations | 6/10 | Live Vercel site works, but three production projects and no CI/staging controls |
| Documentation/governance | 5/5 | Baseline operational/security documentation added by this review |

## Release-blocking checklist

- [ ] Production Supabase schema, policies, functions, auth configuration, secrets, and logs are reviewed from the correct project.
- [ ] Cross-tenant negative tests pass for every table, function, export, backup, AI, support, and payment path.
- [ ] Anonymous direct reads/writes and legacy browser restore paths cannot access production tenant data.
- [ ] Password reset never returns/displays OTP; TOTP secrets never leave trusted boundaries; temporary passwords are not emailed.
- [ ] Password/session security meets an approved standard with server-side rate limits, expiry, revocation, and MFA recovery.
- [ ] Razorpay amount/ownership are server-derived; signatures and webhooks are verified; events are idempotent and reconciled.
- [ ] Financial mutations are transactional and auditable; concurrent updates cannot overwrite arrays silently.
- [ ] Independent backups/PITR are enabled and a complete restore test has passed.
- [ ] Backend source, schema migrations, secret inventory, and infrastructure configuration are version-controlled.
- [ ] One canonical production Vercel project remains; preview deployments use no production secrets/data.
- [ ] CI runs tests, secret scanning, dependency checks, and a staging smoke test before protected-branch deployment.
- [ ] Security headers are verified from the deployed HTTP response and Razorpay checkout is regression-tested.
- [ ] Monitoring/alerting, incident ownership, privacy retention, and support escalation are operational.

## Functional smoke tests

Test with synthetic data only until the blockers close: platform/community/resident login; password change and reset; role-denied navigation and APIs; owner/tenant creation; invoice generation; partial payment and duplicate submission; admin approval/rejection; Razorpay success/failure/replayed webhook; expense/report totals; import validation; amenities; visitors/security gate flow; support; notice publication; logout/session expiry; and cross-tenant attempts for every flow.

## Performance and capacity gaps

The browser loads a 1 MB source document and entire tenant JSON collections. Login without a community hash can fan out across communities. Whole-array writes and client rendering will degrade with tenant growth. Establish budgets (for example p95 page interaction, API latency, error rate, bundle size, maximum tenant records), then load-test representative large communities and simultaneous financial writes.

## Manual production actions

1. Connect the correct Supabase and Vercel projects to a controlled staging review.
2. Export and securely escrow current schema/policies/functions/configuration without exposing secrets.
3. Complete the security and isolation test matrix; remediate blockers through reviewed migrations.
4. Consolidate Vercel projects and configure branch protection/deployment approvals.
5. Deploy headers to preview, validate login/EmailJS/Razorpay, then approve production deployment.
6. Run backup restore and incident tabletop exercises; record owners and actual timings.

Items 1–6 are **REQUIRES MANUAL PRODUCTION APPROVAL** where they touch live data or configuration.
