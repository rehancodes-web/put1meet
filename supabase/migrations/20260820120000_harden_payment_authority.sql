-- Server-authoritative Razorpay order and webhook ledger.
-- Apply in staging first. This migration does not alter existing community data.

create table if not exists public.payment_orders (
  id uuid primary key default gen_random_uuid(),
  razorpay_order_id text not null unique,
  community_id text not null,
  invoice_id text not null,
  owner_id text not null,
  amount_paise bigint not null check (amount_paise > 0),
  currency text not null default 'INR' check (currency = 'INR'),
  status text not null default 'created' check (status in ('created', 'captured', 'failed', 'refunded')),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '24 hours'),
  captured_at timestamptz,
  razorpay_payment_id text unique
);

create index if not exists payment_orders_tenant_invoice_idx
  on public.payment_orders (community_id, invoice_id, created_at desc);

create table if not exists public.payment_events (
  event_id text primary key,
  razorpay_payment_id text not null unique,
  razorpay_order_id text not null,
  payload_sha256 text not null,
  status text not null default 'processing' check (status in ('processing', 'processed', 'duplicate', 'failed')),
  received_at timestamptz not null default now(),
  processed_at timestamptz,
  error_code text
);

alter table public.payment_orders enable row level security;
alter table public.payment_orders force row level security;
alter table public.payment_events enable row level security;
alter table public.payment_events force row level security;

revoke all on public.payment_orders from public, anon, authenticated;
revoke all on public.payment_events from public, anon, authenticated;
grant select, insert, update on public.payment_orders to service_role;
grant select, insert, update on public.payment_events to service_role;

comment on table public.payment_orders is
  'Server-only authoritative binding between a Razorpay order and one tenant invoice.';
comment on table public.payment_events is
  'Server-only idempotency ledger for verified Razorpay webhook events.';

alter default privileges for role postgres in schema public
  revoke select, insert, update, delete on tables from anon, authenticated;
alter default privileges for role postgres in schema public
  revoke execute on functions from public, anon, authenticated;
alter default privileges for role postgres in schema public
  revoke usage, select on sequences from anon, authenticated;

-- Preserve the current server-only design for legacy KV and security tables.
alter table public.platform_kv force row level security;
alter table public.community_kv force row level security;
revoke all on public.platform_kv from public, anon, authenticated;
revoke all on public.community_kv from public, anon, authenticated;

drop policy if exists deny_all_platform_kv on public.platform_kv;
create policy deny_all_platform_kv on public.platform_kv
  as restrictive for all to public using (false) with check (false);
drop policy if exists deny_all_community_kv on public.community_kv;
create policy deny_all_community_kv on public.community_kv
  as restrictive for all to public using (false) with check (false);
