-- The payment ledger is server-only. Explicit deny policies document that
-- boundary and keep the Supabase security advisor free of ambiguity.
drop policy if exists "payment_orders_deny_client_access" on public.payment_orders;
create policy "payment_orders_deny_client_access"
on public.payment_orders
as restrictive
for all
to anon, authenticated
using (false)
with check (false);

drop policy if exists "payment_events_deny_client_access" on public.payment_events;
create policy "payment_events_deny_client_access"
on public.payment_events
as restrictive
for all
to anon, authenticated
using (false)
with check (false);
