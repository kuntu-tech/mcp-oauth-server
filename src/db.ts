import { createClient } from "@supabase/supabase-js";
import { CONFIG } from "./config";

if (!CONFIG.supabase?.url) {
  throw new Error(
    "Supabase URL is not configured. Set SUPABASE_URL in the environment."
  );
}

if (!CONFIG.supabase?.serviceRoleKey) {
  throw new Error(
    "Supabase service role key is not configured. Set SUPABASE_SERVICE_ROLE_KEY in the environment."
  );
}

export const supabase = createClient(CONFIG.supabase.url, CONFIG.supabase.serviceRoleKey, {
  auth: {
    persistSession: false,
  },
  db: {
    schema: CONFIG.supabase.schema as any,
  },
});

export default supabase;
