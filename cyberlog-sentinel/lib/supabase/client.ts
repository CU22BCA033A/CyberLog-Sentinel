'use client';
import { createClient } from '@supabase/supabase-js';

let client: ReturnType<typeof createClient<any>> | null = null;

export function getSupabaseClient() {
  if (!client) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL!;
    const key = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
    client = createClient<any>(url, key);
  }
  return client;
}
