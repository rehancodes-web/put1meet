# Disaster Recovery

## Recovery priorities

1. Protect people and stop unauthorized access or payment activity.
2. Preserve evidence and establish an incident timeline.
3. Restore identity, tenant isolation, invoices, and payments before convenience modules.
4. Reconcile financial state with Razorpay/bank records before reopening mutations.

## Runbook

1. Declare the incident, appoint incident commander, record timestamps, and restrict communications to an approved channel.
2. If compromise is suspected, disable affected deployments/functions, revoke sessions, rotate exposed secrets, and preserve logs. Do not destroy forensic evidence.
3. Identify the last known-good deployment and database recovery point.
4. Restore into an isolated environment first. Apply version-matched migrations and functions.
5. Validate backup integrity, counts, tenant-isolation negative tests, administrator access, invoices/payment totals, webhook replay/idempotency, and storage links.
6. Reconcile Razorpay orders/payments/refunds and queued notifications. Do not resend reminders without idempotency checks.
7. Cut over deliberately, monitor errors/latency/auth failures, and keep rollback available.
8. Notify affected users/regulators when legally required; complete a blameless review and track corrective actions.

## Scenario notes

- **Bad frontend deploy:** roll back the canonical Vercel project to a reviewed deployment; invalidate caches; smoke-test login and payments.
- **Database deletion/corruption:** stop writes; PITR/restore to isolated project; reconcile deltas; rotate credentials if compromise is possible.
- **Cross-tenant exposure:** stop affected endpoints immediately; preserve query/function logs; identify records and users affected; notify counsel/privacy lead.
- **Payment inconsistency:** disable new payment initiation; trust signed gateway/webhook/bank evidence over browser state; reconcile before reopening.
- **Provider outage:** degrade to read-only where safe, queue idempotent work, communicate status, and avoid client-side retry storms.

Run a tabletop exercise twice yearly and a technical restore quarterly. Record actual RPO/RTO, gaps, owners, and due dates.
