import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';
import { isInternalIP, enrichIPGeo } from '@/lib/utils/ip';

export async function GET(req: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();
    const { searchParams } = new URL(req.url);
    const ip = searchParams.get('ip');
    const jobId = searchParams.get('job_id');

    if (!ip) return NextResponse.json({ error: 'IP required' }, { status: 400 });

    let query = supabase
      .from('log_events')
      .select('*')
      .eq('source_ip', ip)
      .order('timestamp', { ascending: false })
      .limit(200);

    if (jobId) query = query.eq('job_id', jobId);

    const { data: events } = await query;

    const failures = events?.filter(e => e.outcome === 'failure').length ?? 0;
    const successes = events?.filter(e => e.outcome === 'success').length ?? 0;
    const users = [...new Set(events?.map(e => e.username).filter(Boolean))] as string[];
    const timestamps = events?.map(e => new Date(e.timestamp).getTime()) ?? [];
    const firstSeen = timestamps.length ? new Date(Math.min(...timestamps)).toISOString() : null;
    const lastSeen = timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : null;

    // Classify threat type
    let classification = 'Unknown';
    if (failures > 50) classification = 'Brute Forcer';
    else if (users.length > 5) classification = 'Credential Stuffer';
    else if (events?.some(e => e.event_type === 'ssh_invalid_user')) classification = 'Scanner';
    else if (failures > 10) classification = 'Password Guesser';

    // Geo enrichment (best effort)
    const geo = await enrichIPGeo(ip);

    return NextResponse.json({
      ip,
      is_internal: isInternalIP(ip),
      geo_country: geo.country,
      geo_city: geo.city,
      total_events: events?.length ?? 0,
      total_failures: failures,
      total_successes: successes,
      targeted_users: users,
      first_seen: firstSeen,
      last_seen: lastSeen,
      classification,
      events: events?.slice(0, 50) ?? [],
    });
  } catch (err) {
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
