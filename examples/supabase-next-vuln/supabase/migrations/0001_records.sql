-- Per-user records. This is the data an IDOR attack targets.
create table if not exists public.records (
  id bigint primary key generated always as identity,
  user_id uuid references auth.users (id),
  secret text not null
);

-- Supabase exposes every public table through PostgREST. These grants are the
-- platform default; row-level security is the ONLY thing standing between a
-- logged-in user and everyone else's rows.
grant select on public.records to anon, authenticated;

-- THE VULNERABILITY: row-level security is never enabled. With the grant above,
-- any logged-in user (indeed anyone holding the public anon key) can read every
-- row by querying /rest/v1/records. Four of five audited vibe-coded apps had this.
-- (The fix loop appends `enable row level security` + an owner policy here.)
