import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';

export const runtime = 'nodejs';

export async function GET(_req: NextRequest) {
  const results: Record<string, unknown> = {};

  // Check env vars exist (don't expose values)
  results.env = {
    NEXT_PUBLIC_SUPABASE_URL: !!process.env.NEXT_PUBLIC_SUPABASE_URL,
    SUPABASE_SERVICE_ROLE_KEY: !!process.env.SUPABASE_SERVICE_ROLE_KEY,
    NEXT_PUBLIC_SUPABASE_ANON_KEY: !!process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    url_value: process.env.NEXT_PUBLIC_SUPABASE_URL?.slice(0, 30) + '...',
  };

  // Test Supabase connection
  try {
    const supabase = createServerSupabaseClient();
    const { data, error } = await supabase
      .from('upload_jobs')
      .select('id, filename, status, user_id, created_at')
      .order('created_at', { ascending: false })
      .limit(5);

    results.supabase_connection = 'OK';
    results.upload_jobs = data ?? [];
    results.upload_jobs_error = error?.message ?? null;

    const { count: eventCount } = await supabase
      .from('log_events')
      .select('*', { count: 'exact', head: true });
    results.event_count = eventCount;

    const { count: incidentCount } = await supabase
      .from('incidents')
      .select('*', { count: 'exact', head: true });
    results.incident_count = incidentCount;

  } catch (err) {
    results.supabase_connection = 'FAILED';
    results.supabase_error = err instanceof Error ? err.message : String(err);
  }

  return NextResponse.json(results, { status: 200 });
}
