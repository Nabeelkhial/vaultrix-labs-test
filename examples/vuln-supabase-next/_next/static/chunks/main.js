import{createClient}from"@supabase/supabase-js";
const URL="https://demo123.supabase.co";
const ANON="eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicm9sZSI6ICJhbm9uIiwgImV4cCI6IDIwMDAwMDAwMDB9.ZmFrZXNpZ25hdHVyZV9ub3RfcmVhbF8xMjM0";
const ADMIN="eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJpc3MiOiAic3VwYWJhc2UiLCAicm9sZSI6ICJzZXJ2aWNlX3JvbGUiLCAiZXhwIjogMjAwMDAwMDAwMH0.ZmFrZXNpZ25hdHVyZV9ub3RfcmVhbF8xMjM0";  // leaked by the AI that wrote this
const STRIPE="sk_live_REDACTED";
export const db=createClient(URL,ADMIN);
