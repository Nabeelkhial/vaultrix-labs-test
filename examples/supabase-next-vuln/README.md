# supabase-next-vuln

A **real** minimal Supabase + Next.js app with the classic vibe-coding bug:
`public.records` is exposed through PostgREST with **row-level security disabled**,
so any logged-in user can read everyone's rows.

Used to prove the `supabase-next` sandbox path end to end: `vaultrix attack --repo
<this> --stack supabase-next` stands the real stack up with `supabase start`, seeds
two users, logs in as one, and reads the other's row (PROVEN). `vaultrix fix` then
appends `enable row level security` + an owner policy to the migration, `db reset`s,
and re-proves the hole closed.

All data is fake and seeded at runtime. Requires the Supabase CLI + Docker.
