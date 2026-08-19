create table if not exists public.auth_rate_limits (
  key text primary key check (length(key) between 1 and 255),
  window_started_at timestamptz not null default now(),
  attempts integer not null default 0 check (attempts >= 0),
  blocked_until timestamptz,
  updated_at timestamptz not null default now()
);
alter table public.auth_rate_limits enable row level security;
alter table public.auth_rate_limits force row level security;
revoke all on public.auth_rate_limits from anon, authenticated;

create or replace function public.consume_auth_rate_limit(
  p_key text, p_limit integer, p_window_seconds integer
) returns table(allowed boolean, attempts integer, blocked_until timestamptz)
language plpgsql security definer set search_path = public
as $$
declare v_row public.auth_rate_limits;
begin
  if p_key is null or length(p_key) = 0 or p_limit < 1 or p_window_seconds < 1 then
    return query select false, 0, now() + interval '1 hour'; return;
  end if;
  insert into public.auth_rate_limits(key, window_started_at, attempts, blocked_until, updated_at)
  values (p_key, now(), 1, null, now())
  on conflict (key) do update set
    attempts = case when now() - auth_rate_limits.window_started_at >= make_interval(secs => p_window_seconds) then 1 else auth_rate_limits.attempts + 1 end,
    window_started_at = case when now() - auth_rate_limits.window_started_at >= make_interval(secs => p_window_seconds) then now() else auth_rate_limits.window_started_at end,
    blocked_until = case when now() - auth_rate_limits.window_started_at >= make_interval(secs => p_window_seconds) then null when auth_rate_limits.attempts + 1 > p_limit then now() + make_interval(secs => p_window_seconds) else auth_rate_limits.blocked_until end,
    updated_at = now()
  returning * into v_row;
  return query select v_row.attempts <= p_limit, v_row.attempts, v_row.blocked_until;
end;
$$;
revoke all on function public.consume_auth_rate_limit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_auth_rate_limit(text, integer, integer) to service_role;
