# WhatsApp and SMS Due Reminders

## Provider and behavior

The implementation uses MSG91 for both channels from the Supabase Edge Function `send-due-reminders`. Provider credentials never enter the browser. Each run loads outstanding invoices from the existing `community_kv` model, groups them by owner, validates Indian mobile numbers, sends the approved templates, and records an idempotency claim in `notification_delivery_log`.

The endpoint defaults to `dryRun: true`. One owner/channel/fingerprint can be processed only once per calendar day. WhatsApp and SMS are independent: failure of one does not suppress the other.

## Consent

Production defaults to explicit consent. Add these booleans to each owner record after obtaining and recording consent:

```json
{
  "whatsappOptIn": true,
  "smsOptIn": true
}
```

Do not disable `DUE_REMINDER_REQUIRE_OPT_IN` without legal/compliance approval. Provide an opt-out mechanism and retain consent evidence. India SMS traffic requires an approved DLT entity, header/sender, and content template matching the message exactly.

## MSG91 templates

Create and obtain approval for:

- WhatsApp utility template name: `community_due_reminder`
- Language: `en` (or the exact approved language code)
- Body variables in order: resident name, community name, outstanding amount, invoice count
- SMS Flow/DLT template variables: `VAR1` name, `VAR2` community, `VAR3` amount, `VAR4` invoice count

Suggested content, adjusted to match approved DLT/WhatsApp wording exactly:

> Hello {{1}}, {{2}} shows outstanding community dues of INR {{3}} across {{4}} invoice(s). Please sign in to review or pay. Ignore this message if already paid.

## Staging installation

1. Create a real timestamped migration with Supabase CLI and copy the reviewed contents of `supabase/migrations/notification_delivery_log.sql` into it.
2. Apply it to a non-production project and run Supabase security/performance advisors.
3. Deploy `supabase/functions/send-due-reminders` with JWT verification disabled only because it uses a separate high-entropy `x-cron-secret`. Keep the function secret unguessable and rotate it periodically.
4. Configure Edge Function secrets from `.env.example`. Supabase automatically supplies `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`; never place either service-role value in frontend code.
5. Give synthetic owners consent flags and Indian test mobile numbers.
6. Invoke with the header `x-cron-secret` and body `{ "dryRun": true }`. Confirm counts and ledger rows; no provider credential is required for dry-run.
7. Invoke one synthetic community with `{ "dryRun": false, "communityId": "..." }`.
8. Confirm MSG91 delivery reports, template-variable order, both channels, idempotent retry behavior, opt-out behavior, invalid-number skips, and no cross-tenant data.

## Schedule

After staging approval, use Supabase Dashboard **Integrations → Cron** to invoke the Edge Function daily. Choose a low-volume time in India and send an HTTP POST with `{ "dryRun": false }`. Store the project URL and cron secret in Supabase Vault; never put the secret directly in migration SQL or Git.

Supabase documents scheduled Edge Function invocation using Cron/`pg_cron` plus `pg_net`, with invocation credentials stored in Vault. Monitor Cron history and Edge Function logs. Keep each run below the Supabase Cron execution limits and introduce batching/queues before tenant volume grows materially.

## Required production controls

- **REQUIRES MANUAL PRODUCTION APPROVAL:** schema migration, function deployment, provider secrets, live template IDs, cron creation, and changing opt-in defaults.
- MSG91 delivery webhooks should update final delivery status; `accepted` currently means the provider accepted the API request, not handset delivery.
- Add rate/batch limits before large-scale launch.
- Do not log message bodies, mobile numbers, auth keys, or resident records.
- The existing KV model can lose concurrent updates; migrate invoices/owners to normalized tenant-scoped tables before relying on this for financial compliance.

Official references: [MSG91 SMS API](https://docs.msg91.com/sms/send-sms), [MSG91 WhatsApp template API](https://docs.msg91.com/whatsapp/template-bulk), and [Supabase scheduled Edge Functions](https://supabase.com/docs/guides/functions/schedule-functions).
