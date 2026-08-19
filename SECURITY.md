# Security Policy

## Reporting a vulnerability

Do not open a public GitHub issue. Report vulnerabilities privately to the repository owner or the security contact configured for the production service. Include the affected URL, reproducible steps, impact, and any supporting request/response details. Do not include resident data, credentials, payment information, or access tokens in email or issue text.

The maintainers should acknowledge a report within two business days, triage severity within five business days, and coordinate disclosure only after a fix is deployed.

## Supported version

Only the version deployed to `https://www.ourcommunity.it.com/` is intended to receive security fixes. Preview deployments are not supported production environments and must not contain production data.

## Rules for contributors

- Never commit passwords, service-role keys, database credentials, Razorpay secrets, EmailJS private credentials, resident exports, or backup files.
- Supabase publishable/anonymous keys are public identifiers, not authorization. RLS and server-side authorization remain mandatory.
- Every tenant-owned database row must carry a non-null `community_id`, with RLS verified using cross-tenant negative tests.
- Payment amount, invoice ownership, tenant ownership, signatures, and idempotency must be verified server-side.
- Do not expose password-reset OTPs or TOTP secrets to logs, browser storage, third-party QR services, or client-visible development responses.
- Changes to production RLS, auth, payments, DNS, data retention, or backups require a reviewed migration, rollback plan, and manual production approval.

See [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) for the current assessment and unresolved blockers.
