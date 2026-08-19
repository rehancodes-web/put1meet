# Deployment

## Current state

The repository contains a static `index.html` and is deployed on Vercel. GitHub displayed 52 deployments and three active production projects/environments for the repository. The canonical public URL is `https://www.ourcommunity.it.com/`. No CI workflow, staging configuration, build manifest, branch protection, or deployment script exists in this snapshot.

## Safe deployment process

1. Work on a short-lived branch and review the exact diff.
2. Run local static validation and the full synthetic-data smoke suite.
3. Deploy to a preview/staging project with separate Supabase, Razorpay test mode, email/message test recipients, and no production data/secrets.
4. Inspect actual HTTP headers; test login/reset/MFA, tenant denials, imports, reports, and Razorpay test success/failure.
5. Obtain named approval for production. Database/RLS/auth/payment/DNS/secret changes require a backup and rollback plan.
6. Deploy one immutable revision to the single canonical production project.
7. Run read-only/synthetic post-deploy checks, monitor error/auth/payment metrics, and record the release revision.
8. Roll back the frontend immediately on regression; use forward-only reviewed database recovery unless a tested reversible migration exists.

## Vercel configuration

`vercel.json` adds response-level security headers. Because the application relies on inline code and Razorpay frames/scripts, deploy this first to preview and verify browser console CSP reports and checkout. HSTS is appropriate only when all served subdomains are HTTPS; `preload` is intentionally not enabled.

Consolidating/deleting duplicate Vercel projects and changing domain/DNS attachment are **REQUIRES MANUAL PRODUCTION APPROVAL**. First identify which project owns the custom domain, environment variables, deployment protection, logs, and rollback history.

## Environment matrix

| Environment | Data | Integrations | Deployment |
|---|---|---|---|
| Local | Synthetic only | Supabase local/staging; provider mocks/test mode | Local static server |
| Preview | Synthetic per branch | Dedicated non-production Supabase; Razorpay test; allow-listed email/messages | Vercel preview |
| Staging | Sanitized/synthetic representative scale | Dedicated staging secrets and webhooks | Protected staging project |
| Production | Approved resident/financial data | Production Supabase/provider secrets | One canonical protected project |

Never reuse production database credentials, service-role tokens, webhook secrets, resident exports, or live messaging recipients in local/preview environments.

## GitHub controls to enable

- Protect `main`: pull request, at least one reviewer, required checks, dismiss stale approvals, restrict force push/deletion.
- Pin GitHub Actions to reviewed full commit SHAs and grant read-only default token permissions.
- Enable secret scanning/push protection and dependency/security updates when the plan and repository structure support them.
- Add CODEOWNERS for security-sensitive paths and require approval for auth, RLS, payments, deployment, and secrets configuration.
