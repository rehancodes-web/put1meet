# Monitoring and Alerting

## Minimum signals

Collect structured, correlated events from Vercel, every Edge Function, Supabase/Postgres, Razorpay webhooks, Email/WhatsApp/SMS delivery providers, scheduled jobs, and the browser error tracker. Use a request/correlation ID and tenant ID, but never log passwords, OTP/TOTP secrets, session tokens, payment secrets, message bodies containing personal data, or full resident records.

| Signal | Alert example |
|---|---|
| Availability/latency | Login/bootstrap or payment p95 above objective; sustained 5xx rate |
| Authentication | Reset/login failure spike, lockouts, MFA recovery, anomalous platform access |
| Tenant isolation | Any policy-denied cross-tenant attempt; null/unknown community ID |
| Payments | Webhook signature failure, duplicate/replayed event, order/payment mismatch, unreconciled payment age |
| Notifications | Queue backlog, provider failure/latency, opt-out violation, duplicate reminder |
| Data | KV/migration write failure, concurrency conflict, financial control-total mismatch |
| Backups | Backup age exceeds RPO, PITR unavailable, restore exercise failed |
| Deployment | Production error regression, CSP violation spike, unexpected production project deployment |

## Service objectives

Define and approve SLOs before launch. Initial candidates: 99.9% monthly availability for login and read access, 99.5% for mutations, p95 API latency under 1 second excluding third-party checkout, and 99% of verified payment webhooks processed within 5 minutes. Use error-budget policy to stop feature releases when reliability is below target.

## Operational requirements

- Dashboards must separate production/staging and support filtering by hashed tenant identifier.
- Alert routes require primary/secondary owners and documented acknowledgement/escalation times.
- Security and financial logs need tamper-resistant retention with tightly controlled access.
- Synthetic tests should cover login/bootstrap and a non-money-changing API; payment canaries must never create accidental charges.
- Review access and alert usefulness quarterly. Runbooks should link directly from alerts.
