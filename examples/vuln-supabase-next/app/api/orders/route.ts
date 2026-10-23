import { createClient } from "@supabase/supabase-js";

// No auth check anywhere in this file: the id comes straight from the caller.
const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const { data } = await db.from("orders").select("*").eq("id", id).single();
  return Response.json(data);
}
