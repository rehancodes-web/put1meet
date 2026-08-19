-- Auth/session/reset records are server-only. Force RLS even for roles that
-- could otherwise bypass ordinary row-security checks.
alter table public.platform_sessions force row level security;
alter table public.community_sessions force row level security;
alter table public.platform_mfa_challenges force row level security;
alter table public.community_mfa_challenges force row level security;
alter table public.platform_password_resets force row level security;
alter table public.community_password_resets force row level security;

revoke all on public.platform_sessions, public.community_sessions,
  public.platform_mfa_challenges, public.community_mfa_challenges,
  public.platform_password_resets, public.community_password_resets
from anon, authenticated;

alter default privileges in schema public
  revoke all on tables from anon, authenticated;
