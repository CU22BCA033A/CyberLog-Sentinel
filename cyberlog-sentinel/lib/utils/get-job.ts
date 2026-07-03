import { getSupabaseClient } from '@/lib/supabase/client';

export async function getLatestJobId(): Promise<string | null> {
  const supabase = getSupabaseClient();
  const { data: { session } } = await supabase.auth.getSession();
  const userId = session?.user?.id;

  if (userId) {
    const { data } = await supabase
      .from('upload_jobs')
      .select('id')
      .eq('user_id', userId)
      .eq('status', 'complete')
      .order('created_at', { ascending: false })
      .limit(1);
    if (data && data.length > 0) return data[0].id;
  }

  // Fallback: any complete job
  const { data } = await supabase
    .from('upload_jobs')
    .select('id')
    .eq('status', 'complete')
    .order('created_at', { ascending: false })
    .limit(1);
  return data?.[0]?.id ?? null;
}
