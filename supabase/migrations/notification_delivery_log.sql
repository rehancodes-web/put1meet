-- REQUIRES MANUAL PRODUCTION APPROVAL.
-- Apply to staging first and run cross-tenant/security tests.
create table if not exists public.notification_delivery_log (
  id bigint generated always as identity primary key,
  community_id text not null,
  owner_id text not null,
  channel text not null check (channel in ('whatsapp', 'sms')),
  reminder_date date not null,
  dues_fingerprint text not null,
  status text not null check (status in ('dry_run', 'processing', 'accepted', 'failed')),
  provider_response jsonb,
  error_code text,
  created_at timestamptz not null default now(),
  sent_at timestamptz,
  unique (community_id, owner_id, channel, reminder_date, dues_fingerprint)
);

alter table public.notification_delivery_log enable row level security;
revoke all on table public.notification_delivery_log from anon, authenticated;

comment on table public.notification_delivery_log is
  'Server-only idempotency and delivery audit ledger. Provider responses must not contain message bodies or credentials.';

create index if not exists notification_delivery_log_lookup_idx
  on public.notification_delivery_log (community_id, owner_id, reminder_date desc);
