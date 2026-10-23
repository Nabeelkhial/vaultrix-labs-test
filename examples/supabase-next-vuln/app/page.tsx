// Minimal Next app. The security surface that matters is Supabase's PostgREST API
// guarded (or not) by row-level security, which this app talks to from the browser.
import { createClient } from "@supabase/supabase-js";
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
);
export default async function Page() {
  const { data } = await supabase.from("records").select("*");
  return <pre>{JSON.stringify(data, null, 2)}</pre>;
}
