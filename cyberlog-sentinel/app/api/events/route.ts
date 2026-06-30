import { NextRequest, NextResponse } from 'next/server';
import { createServerSupabaseClient } from '@/lib/supabase/server';

export async function GET(req: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();
    const { searchParams } = new URL(req.url);

    const page = parseInt(searchParams.get('page') ?? '1', 10);
    const limit = Math.min(parseInt(searchParams.get('limit') ?? '50', 10), 200);
    const offset = (page - 1) * limit;

    const jobId = searchParams.get('job_id');
    const severity = searchParams.get('severity');
    const outcome = searchParams.get('outcome');
    const eventType = searchParams.get('event_type');
    const sourceIp = searchParams.get('source_ip');
    const username = searchParams.get('username');
    const search = searchParams.get('search');
    const sortBy = searchParams.get('sort_by') ?? 'timestamp';
    const sortDir = searchParams.get('sort_dir') === 'asc' ? true : false;

    let query = supabase
      .from('log_events')
      .select('*', { count: 'exact' })
      .order(sortBy, { ascending: sortDir })
      .range(offset, offset + limit - 1);

    if (jobId) query = query.eq('job_id', jobId);
    if (severity) query = query.eq('severity', severity);
    if (outcome) query = query.eq('outcome', outcome);
    if (eventType) query = query.eq('event_type', eventType);
    if (sourceIp) query = query.eq('source_ip', sourceIp);
    if (username) query = query.ilike('username', `%${username}%`);
    if (search) query = query.ilike('raw_line', `%${search}%`);

    const { data, count, error } = await query;

    if (error) {
      return NextResponse.json({ error: error.message }, { status: 500 });
    }

    return NextResponse.json({
      data,
      total: count ?? 0,
      page,
      limit,
      totalPages: Math.ceil((count ?? 0) / limit),
    });
  } catch (err) {
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}

export async function PATCH(req: NextRequest) {
  try {
    const supabase = createServerSupabaseClient();
    const body = await req.json() as { id: string; analyst_note?: string; is_false_positive?: boolean };
    const { id, analyst_note, is_false_positive } = body;

    const updates: Record<string, unknown> = {};
    if (analyst_note !== undefined) updates.analyst_note = analyst_note;
    if (is_false_positive !== undefined) updates.is_false_positive = is_false_positive;

    const { data, error } = await supabase
      .from('log_events')
      .update(updates)
      .eq('id', id)
      .select()
      .single();

    if (error) return NextResponse.json({ error: error.message }, { status: 500 });
    return NextResponse.json(data);
  } catch (err) {
    return NextResponse.json({ error: 'Internal error' }, { status: 500 });
  }
}
