# Backup Strategy

## Current state

The application can create manual or daily browser-triggered snapshots and stores them under `backupSnapshots` in the same `community_kv` database. It can download/import JSON. This is an export convenience, not disaster recovery: it shares the same failure domain, runs only when a browser invokes it, contains no independently verified encryption/immutability, and can be overwritten through the application.

## Production strategy

Target objectives must be approved by the business; a reasonable starting point for financial/community data is RPO 15 minutes and RTO 4 hours.

- Enable the Supabase backup/PITR capability appropriate to the production plan.
- Create an independent, encrypted, access-logged backup copy in a separate project/account or storage boundary.
- Back up schema migrations, Edge Function source/configuration, and non-secret infrastructure configuration in Git.
- Back up storage objects and required metadata; database backups alone do not automatically prove object recovery.
- Keep daily copies for 35 days, monthly copies for 12 months, and an annual copy only if legal/business retention requires it.
- Separate backup operators from application admins; require MFA and least privilege.
- Monitor backup freshness and failures. Never include raw secrets in backup exports.
- Run a documented restore exercise quarterly into an isolated project, compare row counts and financial control totals, test authentication/isolation, and destroy the exercise environment securely.

Retention must follow Indian legal, tax, privacy, and contractual requirements determined by qualified counsel. Resident exports should be minimized and deleted when their purpose expires.
