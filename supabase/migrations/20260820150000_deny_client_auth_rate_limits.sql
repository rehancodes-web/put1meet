create policy "auth_rate_limits_deny_client_access"
on public.auth_rate_limits as restrictive
for all to anon, authenticated
using (false) with check (false);
